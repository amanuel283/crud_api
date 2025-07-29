package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/izymalhaw/go-crud/yishakterefe/internal/services/auth"
	person_service "github.com/izymalhaw/go-crud/yishakterefe/internal/services/person"
)

// Server represents the HTTP server for the application.
type Server struct {
	port          string
	router        *http.ServeMux
	PersonService person_service.PersonServiceAbstrcatImpl
	authService   *auth.Service
	authHandler   *AuthHandler
	logger        *slog.Logger
}

// NewApp initializes a new Server instance.
func NewApp(
	port int,
	personService person_service.PersonServiceAbstrcatImpl,
	authService *auth.Service,
	authHandler *AuthHandler,
	logger *slog.Logger,
) *Server {
	app := &Server{
		port:          strconv.Itoa(port),
		router:        http.NewServeMux(),
		PersonService: personService,
		authService:   authService,
		authHandler:   authHandler,
		logger:        logger,
	}

	// Register routes
	app.Routes()

	// Enable CORS
	wrappedRouter := app.enableCORS(app.router)

	// Replace the original router with wrapped one
	app.router = http.NewServeMux()
	app.router.Handle("/", wrappedRouter)

	return app
}

// Run starts the HTTP server.
func (app *Server) Run() error {
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", app.port), 
		Handler:      app.router,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	shutdownError := make(chan error)

	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit

		app.logger.Info("shutting down server...")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		shutdownError <- srv.Shutdown(ctx)
	}()

	err := srv.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	err = <-shutdownError
	if err != nil {
		return err
	}

	app.logger.Info("server stopped gracefully")
	return nil
}
