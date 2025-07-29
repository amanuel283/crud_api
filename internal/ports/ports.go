package ports

import (
	"context"

	"github.com/google/uuid"
	"github.com/izymalhaw/go-crud/yishakterefe/internal/domain"
)

type PersonRepository interface {
	CreatePerson(ctx context.Context, person domain.Person) error
	GetAllPersons(ctx context.Context, limit, offset int) ([]domain.Person, error)
	UpdatePerson(ctx context.Context, person domain.Person) error
	DeletePerson(ctx context.Context, id uuid.UUID) error
	GetPerson(ctx context.Context, userID uuid.UUID) (*domain.Person, error)
}
