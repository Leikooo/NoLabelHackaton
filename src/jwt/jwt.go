package jwt

import (
	"context"
	"fmt"
	"github.com/go-co-op/gocron"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"
	"net/http"
	"os"
	"strings"
	"time"
)

type jwtError string

const (
	NoSuchUrls           jwtError = "не указан адрес для получения ключей"
	RequestCreationError jwtError = "ошибка формирования запроса"
	RequestExecError     jwtError = "ошибка выполнения запроса"
	NoKeysFound          jwtError = "не удалось получить ключи при первом запуске приложения"
	PingError            jwtError = "в сервисе ноль ключей"
)

func (err jwtError) Error() string {
	return string(err)
}

type JWT struct {
	PublicKeys *jose.JSONWebKeySet
	Client     http.Client
	Scheduler  *gocron.Scheduler
	Urls       []string
}

func (j *JWT) getPublicKeys() {
	newPublicKeys := make([]jose.JSONWebKey, 0)

	for _, url := range j.Urls {
		request, err := http.NewRequest("GET", url, nil)

		if err != nil {
			log.Error(errors.Wrap(err, fmt.Sprintf("%s: %s", RequestCreationError.Error(), err)))
		}

		resp, err := j.Client.Do(request)

		if err != nil {
			log.Error(errors.Wrap(err, fmt.Sprintf("%s: %s", RequestExecError.Error(), err)))
		}

		if resp.StatusCode != 200 {
			log.Error(fmt.Sprintf("код ответа %d по url %s", resp.StatusCode, resp.Request.URL))
		}
		defer resp.Body.Close()

		var a jose.JSONWebKeySet

		err = json.NewDecoder(resp.Body).Decode(&a)

		if err != nil {
			log.Error(fmt.Sprintf("ошибка декодирования json: %s по пути %s", err, resp.Request.URL))
		} else {
			newPublicKeys = append(newPublicKeys, a.Keys...)
		}
	}

	if len(newPublicKeys) == 0 {
		if j.PublicKeys == nil {
			log.Panic(NoKeysFound)
		}
	} else {
		j.PublicKeys = &jose.JSONWebKeySet{Keys: newPublicKeys}
	}

	log.Infof("Получено %d ключей", len(j.PublicKeys.Keys))
}

func (j *JWT) Init(ctx context.Context) error {

	urls := os.Getenv("PUBLIC_KEY_URL")

	if urls == "" {
		return NoSuchUrls
	}
	j.Urls = strings.Split(urls, ",")

	j.Client = http.Client{Timeout: time.Second * 10}
	j.Scheduler = gocron.NewScheduler(time.Local)

	_, err := j.Scheduler.Every(1).Hour().Do(j.getPublicKeys)
	if err != nil {
		return err
	}
	j.Scheduler.StartAsync()

	return nil
}

func (j *JWT) Ping(ctx context.Context) error {
	if len(j.PublicKeys.Keys) != 0 {
		return nil
	}
	return PingError
}

func (j *JWT) Close() error {
	return nil
}

func (j *JWT) Name() string {
	return "jwt"
}
