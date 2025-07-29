package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/izymalhaw/go-crud/yishakterefe/internal/domain"
	"github.com/izymalhaw/go-crud/yishakterefe/internal/ports"
	_ "github.com/lib/pq"
)


type PostgresUserRepo struct {
	db *sql.DB
}

func NewPostgresUserRepo(db *sql.DB) ports.PersonRepository {
	return &PostgresUserRepo{db: db}
}

func (repo *PostgresUserRepo) CreatePerson(ctx context.Context, person domain.Person) error {
	hobbiesJSON, err := json.Marshal(person.Hobbies)
	if err != nil {
		return fmt.Errorf("failed to marshal hobbies: %w", err)
	}

	query := `INSERT INTO persons (id, name, age, hobbies) VALUES ($1, $2, $3, $4)`
	_, err = repo.db.ExecContext(ctx, query,
		person.Id,
		person.Name,
		person.Age,
		hobbiesJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to create person: %w", err)
	}
	return nil
}


func (repo *PostgresUserRepo) GetAllPersons(ctx context.Context, limit, offset int) ([]domain.Person, error) {
	query := `SELECT id, name, age, hobbies FROM persons ORDER BY created_at DESC LIMIT $1 OFFSET $2`
	rows, err := repo.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get persons: %w", err)
	}
	defer rows.Close()

	var persons []domain.Person
	for rows.Next() {
		var person domain.Person
		var hobbiesJSON []byte

		if err := rows.Scan(
			&person.Id,
			&person.Name,
			&person.Age,
			&hobbiesJSON,
		); err != nil {
			return nil, fmt.Errorf("failed to scan person: %w", err)
		}

		if err := json.Unmarshal(hobbiesJSON, &person.Hobbies); err != nil {
			return nil, fmt.Errorf("failed to unmarshal hobbies: %w", err)
		}

		persons = append(persons, person)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return persons, nil
}

func (repo *PostgresUserRepo) UpdatePerson(ctx context.Context, person domain.Person) error {
	hobbiesJSON, err := json.Marshal(person.Hobbies)
	if err != nil {
		return fmt.Errorf("failed to marshal hobbies: %w", err)
	}

	query := `UPDATE persons SET name=$1, age=$2, hobbies=$3, updated_at=NOW() WHERE id=$4`
	result, err := repo.db.ExecContext(ctx, query,
		person.Name,
		person.Age,
		hobbiesJSON,
		person.Id,
	)
	if err != nil {
		return fmt.Errorf("failed to update person: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return errors.New("user not found")
	}
	return nil
}

func (repo *PostgresUserRepo) DeletePerson(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM persons WHERE id=$1`
	result, err := repo.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete person: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return errors.New("user not found")
	}
	return nil
}

func (repo *PostgresUserRepo) GetPerson(ctx context.Context, userID uuid.UUID) (*domain.Person, error) {
	query := `SELECT id, name, age, hobbies FROM persons WHERE id=$1`
	row := repo.db.QueryRowContext(ctx, query, userID)

	var person domain.Person
	var hobbiesJSON []byte

	if err := row.Scan(
		&person.Id,
		&person.Name,
		&person.Age,
		&hobbiesJSON,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to scan person: %w", err)
	}

	if err := json.Unmarshal(hobbiesJSON, &person.Hobbies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal hobbies: %w", err)
	}

	return &person, nil
}
