package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	_ "github.com/izymalhaw/go-crud/yishakterefe/docs"
	"github.com/izymalhaw/go-crud/yishakterefe/internal/api/dto"
	"github.com/izymalhaw/go-crud/yishakterefe/internal/domain"
	"github.com/izymalhaw/go-crud/yishakterefe/internal/util"
)

// @Summary Create a new person
// @Description This endpoint creates a new person entry.
// @Tags person
// @Accept json
// @Produce json
// @Param dto.PersonRequest body dto.PersonRequest true "Person Data"
// @Success 200 {object} dto.PersonResponse
// @Failure 400 {object} dto.PersonResponse
// @Failure 500 {object} dto.PersonResponse
// @Router /api/v1/person/create [post]
func (s *Server) CreatePerson() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req dto.PersonRequest

		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		ctx := r.Context()
		id := uuid.New()
		err = s.PersonService.CreatePerson(ctx, domain.Person{
			Id:      id,
			Name:    req.Name,
			Age:     req.Age,
			Hobbies: req.Hobbies,
		})
		if err != nil {
			s.logger.Error("Error creating person: %v", err.Error(), "")
			util.WriteErrorResponse(w, http.StatusInternalServerError, "")
			return
		}
		response := fmt.Sprintf("successfully created person with ID: %s", id.String())
		util.WriteSuccessResponse(w, nil, response)
	}
}

// @Summary Get all persons
// @Description Retrieves a list of persons with optional pagination.
// @Tags person
// @Accept json
// @Produce json
// @Param limit query int false "Limit number of results"
// @Param offset query int false "Offset for pagination"
// @Success 200 {array} dto.PersonResponse
// @Failure 400 {object} dto.PersonResponse
// @Failure 500 {object} dto.PersonResponse
// @Router /api/v1/person [get]
func (s *Server) GetPersons() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		limitStr := r.URL.Query().Get("limit")
		offsetStr := r.URL.Query().Get("offset")

		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit <= 0 {
			limit = 10
		}

		offset, err := strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			offset = 0
		}

		data, err := s.PersonService.GetAllPersons(ctx, limit, offset)
		if err != nil {
			s.logger.Error("Error getting persons: %v", err.Error(), "")
			util.WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve persons")
			return
		}

		var response []dto.PersonResponse
		for _, person := range data {
			response = append(response, dto.PersonResponse{
				Id:      person.Id,
				Name:    person.Name,
				Age:     person.Age,
				Hobbies: person.Hobbies,
			})
		}

		util.WriteSuccessResponse(w, response, "Persons retrieved successfully")
	}
}

// @Summary Update a person
// @Description This endpoint updates a person's details.
// @Tags person
// @Accept json
// @Produce json
// @Param personId path string true "Person ID"
// @Param dto.PersonRequest body dto.PersonRequest true "Person Data"
// @Success 200 {object} dto.PersonResponse
// @Failure 400 {object} dto.PersonResponse
// @Failure 500 {object} dto.PersonResponse
// @Router /api/v1/person/{personId} [put]
func (s *Server) UpdatePerson() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		person_id := r.PathValue("personId")
		if person_id == "" {
			util.WriteErrorResponse(w, http.StatusBadRequest, "Invalid request")
			return
		}
		var req dto.PersonRequest

		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		ctx := r.Context()
		err = s.PersonService.UpdatePerson(ctx, domain.Person{
			Id:      uuid.MustParse(person_id),
			Name:    req.Name,
			Age:     req.Age,
			Hobbies: req.Hobbies,
		})
		if err != nil {
			s.logger.Error("Error updating person: %v", err.Error(), "")
			util.WriteErrorResponse(w, http.StatusInternalServerError, "")
			return
		}
		responseString := fmt.Sprintf("Successfully updated person with ID: %s", person_id)
		responseData := dto.PersonResponse{
			Id:      uuid.MustParse(person_id),
			Name:    req.Name,
			Age:     req.Age,
			Hobbies: req.Hobbies,
		}
		util.WriteSuccessResponse(w, responseData, responseString)
	}
}

// @Summary Get Single person
// @Description This endpoint retrieves a single person entry.
// @Tags person
// @Accept json
// @Produce json
// @Param personId path string true "Person ID"
// @Success 200 {object} dto.PersonResponse
// @Failure 400 {object} dto.PersonResponse
// @Failure 500 {object} dto.PersonResponse
// @Router /api/v1/person/{personId} [get]
func (s *Server) GetPerson() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		person_id := r.PathValue("personId")
		if person_id == "" {
			util.WriteErrorResponse(w, http.StatusBadRequest, "Invalid request")
			return
		}
		ctx := r.Context()
		data, err := s.PersonService.GetPerson(ctx, uuid.MustParse(person_id))
		if err != nil {
			s.logger.Error("Error getting person: %v", err.Error(), "")
			util.WriteErrorResponse(w, http.StatusInternalServerError, "")
			return
		}
		responseData := dto.PersonResponse{
			Id:      data.Id,
			Name:    data.Name,
			Age:     data.Age,
			Hobbies: data.Hobbies,
		}
		util.WriteSuccessResponse(w, responseData, "Person retrieved successfully")
	}
}

// @Summary Delete person
// @Description This endpoint deletes a person entry.
// @Tags person
// @Accept json
// @Produce json
// @Param personId path string true "Person ID"
// @Success 200 {string} string "Successfully deleted person"
// @Failure 400 {object} dto.PersonResponse
// @Failure 500 {object} dto.PersonResponse
// @Router /api/v1/person/{personId} [delete]
func (s *Server) DeletePerson() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		person_id := r.PathValue("personId")
		if person_id == "" {
			util.WriteErrorResponse(w, http.StatusBadRequest, "Invalid request")
			return
		}
		ctx := r.Context()
		err := s.PersonService.DeletePerson(ctx, uuid.MustParse(person_id))
		if err != nil {
			s.logger.Error("Error deleting person: %v", err.Error(), "")
			util.WriteErrorResponse(w, http.StatusInternalServerError, "")
			return
		}
		responseString := fmt.Sprintf("Successfully deleted person with ID: %s", person_id)
		util.WriteSuccessResponse(w, nil, responseString)
	}
}
