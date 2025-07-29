package dto

import "github.com/google/uuid"

type PersonRequest struct {
	Name    string   `json:"name" validate:"required"`
	Age     int      `json:"age" validate:"required,gte=0"`
	Hobbies []string `json:"hobbies" validate:"required"`
}

type PersonResponse struct {
	Id      uuid.UUID `json:"id"`
	Name    string    `json:"name"`
	Age     int       `json:"age"`
	Hobbies []string  `json:"hobbies"`
}
