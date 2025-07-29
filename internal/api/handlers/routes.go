package handlers

import (
	"net/http"

	_ "github.com/izymalhaw/go-crud/yishakterefe/docs"
	httpSwagger "github.com/swaggo/http-swagger"
)

// @title Mereb Challenge
// @version 1.0
// @description Mereb Challenge done by @izymalhaw
// @host localhost:8080
// @BasePath /api/v1
func (server *Server) Routes() {
	// Auth route
	server.router.HandleFunc("POST /api/v1/auth/login", server.authHandler.Login())
	// Person routes
	server.router.HandleFunc("POST /api/v1/person/create", server.CreatePerson())
	server.router.HandleFunc("GET /api/v1/person", server.GetPersons())
	server.router.HandleFunc("PUT /api/v1/person/{personId}", server.UpdatePerson())
	server.router.HandleFunc("GET /api/v1/person/{personId}", server.GetPerson())
	server.router.HandleFunc("DELETE /api/v1/person/{personId}", server.DeletePerson())

	server.router.HandleFunc("/", http.HandlerFunc(server.HandleNotFound))
	server.router.HandleFunc("/swagger/", httpSwagger.WrapHandler)
}
