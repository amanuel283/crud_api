# Variables
GO_FILES := $(shell find . -name '*.go' -not -path "./vendor/*")
GO_CMD := go run cmd/main.go
ENV_FILE := .env

# Detect OS (Windows or Linux)
ifeq ($(OS),Windows_NT)
    SHELL := powershell.exe
    LOAD_ENV := . .\dotenv.ps1
else
    SHELL := /bin/bash
    LOAD_ENV := source load_env.sh
endif

# Default target
all: build

# Target to run the Go application with environment variables loaded
run:
ifeq ($(OS),Windows_NT)
	@$(LOAD_ENV); go run cmd/main.go
else
	@$(LOAD_ENV) && go run cmd/main.go
endif

# Build the Go application
build:
	@echo "Building the Go application..."
	go build -o bin/app $(GO_FILES)

# Clean up built files
clean:
	@echo "Cleaning up..."
	rm -rf bin

# Load environment variables and run the Go application in a single step
run-env:
ifeq ($(OS),Windows_NT)
	@$(LOAD_ENV); $(GO_CMD)
else
	@$(LOAD_ENV) && $(GO_CMD)
endif

# Help target to list available commands
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  run         Load environment variables and run the application"
	@echo "  build       Build the Go application"
	@echo "  clean       Clean up built files"
	@echo "  run-env     Load environment variables and run the Go application"
	@echo "  help        Display this help message"


.PHONY: all run build clean run-env help
