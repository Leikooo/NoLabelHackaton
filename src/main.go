package main

import (
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"src/jwt"
	"src/utils"
)

func main() {
	var j jwt.JWT
	router := mux.NewRouter()
	port := os.Getenv("HTTP_PORT")

	utils.InitLogger()

	jwt.Init()
	j.PublicKeys = jwt.PublicKeys

	router.Use(utils.Recovery)
	router.Use(j.JwtAuthentication)

	router.HandleFunc("/auth/login", controllers.login).Methods(http.MethodGet)

	router.HandleFunc("/NoLabel/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	err := http.ListenAndServe(":"+port, router)
	if err != nil {
		log.Printf("problem with server %s", err)
	}
}

var NotImplemented = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Not Implemented"))
})
