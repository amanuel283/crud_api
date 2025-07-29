package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/izymalhaw/go-crud/yishakterefe/internal/domain"
)

// CreateUser adds a new user to the in-memory store.
func (repo *InMemoryUserRepo) CreatePerson(ctx context.Context, person domain.Person) error {
	repo.mu.Lock()
	defer repo.mu.Unlock()

	if _, exists := repo.persons[person.Id]; exists {
		return errors.New("user already exists")
	}

	repo.persons[person.Id] = person
	return nil
}

// GetAllUsers retrieves all users from the in-memory store with pagination.
func (repo *InMemoryUserRepo) GetAllPersons(ctx context.Context, limit, offset int) ([]domain.Person, error) {
	repo.mu.RLock()
	defer repo.mu.RUnlock()

	var result []domain.Person
	count := 0
	for _, user := range repo.persons {
		if count >= offset && len(result) < limit {
			result = append(result, user)
		}
		count++
	}
	return result, nil
}

// UpdateUser updates an existing user in the in-memory store.
func (repo *InMemoryUserRepo) UpdatePerson(ctx context.Context, person domain.Person) error {
	repo.mu.Lock()
	defer repo.mu.Unlock()

	if _, exists := repo.persons[person.Id]; !exists {
		return errors.New("user not found")
	}

	repo.persons[person.Id] = person
	return nil
}

// DeleteUser removes a user from the in-memory store.
func (repo *InMemoryUserRepo) DeletePerson(ctx context.Context, id uuid.UUID) error {
	repo.mu.Lock()
	defer repo.mu.Unlock()

	if _, exists := repo.persons[id]; !exists {
		return errors.New("user not found")
	}

	delete(repo.persons, id)
	return nil
}

// GetUserByID retrieves a user by their ID.
func (repo *InMemoryUserRepo) GetPerson(ctx context.Context, userID uuid.UUID) (*domain.Person, error) {
	repo.mu.RLock()
	defer repo.mu.RUnlock()

	user, exists := repo.persons[userID]
	if !exists {
		return nil, errors.New("user not found")
	}
	return &user, nil
}
