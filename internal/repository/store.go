package repository

import (
	"sync"

	"github.com/google/uuid"
	"github.com/izymalhaw/go-crud/yishakterefe/internal/domain"
)

type InMemoryUserRepo struct {
	mu      sync.RWMutex
	persons map[uuid.UUID]domain.Person
}

func NewInMemoryUserRepo() *InMemoryUserRepo {
	return &InMemoryUserRepo{
		persons: make(map[uuid.UUID]domain.Person),
	}
}
