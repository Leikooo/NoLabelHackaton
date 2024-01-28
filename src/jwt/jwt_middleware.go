package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"src/utils"
	"strconv"
	"strings"
	"time"
)

var PublicKeys *jose.JSONWebKeySet

func (j *JWT) JwtAuthentication(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		notAuth := []string{"/NoLabel/healthcheck"}
		requestPath := r.URL.Path

		//проверяем, не требует ли запрос аутентификации, обслуживаем запрос, если он не нужен
		for _, value := range notAuth {
			if value == requestPath {
				next.ServeHTTP(w, r)
				return
			}
		}

		tokenHeader := r.Header.Get("Authorization") // Получение токена

		if tokenHeader == "" { //Токен отсутствует, возвращаем 403 http-код Unauthorized
			utils.Response(w, nil, 90, 403)
			return
		}

		splitted := strings.Split(tokenHeader, " ") //Токен обычно поставляется в формате `Bearer {token-body}`, мы проверяем, соответствует ли полученный токен этому требованию
		if len(splitted) != 2 {
			utils.Response(w, nil, 92, 401)
			return
		}

		tokenPart := splitted[1] //Получаем вторую часть токена

		// распарсить json
		object, err := jose.ParseSigned(tokenPart)
		if err != nil {
			utils.Response(w, nil, 94, 400)
			return
		}

		keyId := object.Signatures[0].Header.KeyID

		pkey := j.PublicKeys.Key(keyId)

		if pkey == nil {
			utils.Response(w, nil, 94, 400)
			return
		}

		// проверить на валидность
		output, err := object.Verify(pkey[0])
		if err != nil {
			utils.Response(w, nil, 95, 400)
			return
		}

		var j = map[string]interface{}{}

		err = json.Unmarshal(output, &j)

		if err != nil {
			utils.Response(w, nil, 94, 400)
			return
		}

		loc, _ := time.LoadLocation("Europe/Moscow")
		t := time.Now()

		if t.In(loc).Unix() > int64(j["exp"].(float64)) {
			i, err := strconv.ParseInt(strconv.Itoa(int(j["exp"].(float64))), 10, 64)
			if err != nil {
				panic(err)
			}
			tm := time.Unix(i, 0)
			fmt.Println(tm)
			fmt.Printf("Current time is %v\n", int64(j["exp"].(float64)))
			utils.Response(w, nil, 93, 401)
			return
		}

		lang := r.Header.Get("Accept-Language")
		if lang == "" {
			lang = "ru"
		} else {
			lang = r.Header.Get("Accept-Language")
		}

		ctx := context.WithValue(r.Context(), "data", tokenPart)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
