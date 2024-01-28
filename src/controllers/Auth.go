package controllers

import (
	"net/http"
	"src/utils"
)

func login(w http.ResponseWriter, r *http.Request) {
	utils.Response(w, "login", 0, 200)
}
