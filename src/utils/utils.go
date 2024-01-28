package utils

import (
	"encoding/json"
	"net/http"
)

var errorCodes = map[int]interface{}{
	0:  nil,
	90: "Не передан токен",
	91: "Не указан тип токена",
	92: "Проблемы с токеном",
	93: "Токен не действителен",
	94: "Невалидный json",
	95: "JWT не прошел проверку",
}

func Response(w http.ResponseWriter, result interface{}, errorCode int, statusCode int) {
	data := map[string]interface{}{
		"error_code":    errorCode,
		"error_message": errorCodes[errorCode],
		"result":        result}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		defer func() {
			err := recover()
			if err != nil {
				w.WriteHeader(500)
			}

		}()

		next.ServeHTTP(w, r)

	})
}
