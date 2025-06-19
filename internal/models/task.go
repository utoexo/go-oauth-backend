package models

import (
	"time"

	"github.com/google/uuid"
)

/*
Task represents a task in the system.
swagger:model Task

	Example: {
	  "id": "123e4567-e89b-12d3-a456-426614174000",
	  "title": "Write documentation",
	  "description": "Write Swagger docs for the API",
	  "status": "pending",
	  "created_at": "2025-06-18T10:00:00Z",
	  "updated_at": "2025-06-18T10:00:00Z"
	}
*/
type Task struct {
	ID          uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey" json:"id" example:"123e4567-e89b-12d3-a456-426614174000"`
	Title       string    `json:"title" example:"Write documentation"`
	Description string    `json:"description" example:"Write Swagger docs for the API"`
	Status      string    `json:"status" example:"pending"` // e.g., pending, completed
	CreatedAt   time.Time `json:"created_at" example:"2025-06-18T10:00:00Z"`
	UpdatedAt   time.Time `json:"updated_at" example:"2025-06-18T10:00:00Z"`
}

// CreateTaskRequest represents the payload for creating a new task.
// swagger:model CreateTaskRequest
type CreateTaskRequest struct {
	Title       string `json:"title" example:"Task 1"`
	Description string `json:"description,omitempty" example:"Task 1 description"`
	Status      string `json:"status,omitempty" example:"pending"`
}

// UpdateTaskRequest represents the payload for updating a task.
// swagger:model UpdateTaskRequest
type UpdateTaskRequest struct {
	Title       string `json:"title" example:"Updated Task 1"`
	Description string `json:"description,omitempty" example:"Updated Task 1 description"`
	Status      string `json:"status,omitempty" example:"completed"`
}
