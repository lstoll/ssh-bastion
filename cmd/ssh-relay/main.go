package main

import (
	"log"
	"net/http"

	"github.com/lstoll/ssh-bastion/nassh"
	"github.com/sirupsen/logrus"
)

func main() {
	r := nassh.Relay{
		Logger: logrus.New(),
	}

	m := http.NewServeMux()

	m.HandleFunc("/cookie", r.SimpleCookieHandler)
	m.HandleFunc("/proxy", r.ProxyHandler)
	m.HandleFunc("/connect", r.ConnectHandler)

	log.Fatal(http.ListenAndServe(":8080", logRequest(m)))
}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}
