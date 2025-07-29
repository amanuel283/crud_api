package domain

import (
	"github.com/google/uuid"
)

type Person struct {
	Id      uuid.UUID
	Name    string
	Age     int
	Hobbies []string
}
