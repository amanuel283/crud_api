package person_service

import (
	"context"

	"github.com/google/uuid"
	"github.com/izymalhaw/go-crud/yishakterefe/internal/domain"
)

type PersonServiceAbstrcatImpl interface {
	CreatePerson(ctx context.Context, person domain.Person) error
	GetAllPersons(ctx context.Context, limit, offset int) ([]domain.Person, error)
	GetPerson(ctx context.Context, id uuid.UUID) (domain.Person, error)
	UpdatePerson(ctx context.Context, person domain.Person) error
	DeletePerson(ctx context.Context, id uuid.UUID) error
}
