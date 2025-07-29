package handlers

import (
	"net/http"

	"github.com/izymalhaw/go-crud/yishakterefe/internal/util"
)

func (server *Server) HandleNotFound(w http.ResponseWriter, r *http.Request) {
	util.WriteErrorResponse(w, http.StatusNotFound, "404 Not Found")
}
