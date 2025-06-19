package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/ishare/taskapi/internal/models"
	"gorm.io/gorm"
)

type TaskHandler struct {
	DB *gorm.DB
}

func NewTaskHandler(db *gorm.DB) *TaskHandler {
	return &TaskHandler{DB: db}
}

// CreateTask godoc
// @Summary Create a new task
// @Description Creates a new task. Requires JWT access token.
// @Tags Tasks
// @Accept json
// @Produce json
// @Param task body models.CreateTaskRequest true "Task to create"
// @Success 201 {object} models.Task
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Security BearerAuth
// @Router /tasks [post]
func (h *TaskHandler) CreateTask(c *gin.Context) {
	var req models.CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "Invalid request body: "+err.Error())
		return
	}

	// Validate required fields
	if req.Title == "" {
		BadRequest(c, "Title is required")
		return
	}

	task := models.Task{
		ID:          uuid.New(),
		Title:       req.Title,
		Description: req.Description,
		Status:      req.Status,
	}
	if task.Status == "" {
		task.Status = "pending"
	}

	if err := h.DB.Create(&task).Error; err != nil {
		InternalServerError(c, err)
		return
	}

	c.JSON(http.StatusCreated, task)
}

// GetTask godoc
// @Summary Get a task by ID
// @Description Retrieves a task by its ID. Requires JWT access token.
// @Tags Tasks
// @Produce json
// @Param id path string true "Task ID"
// @Success 200 {object} models.Task
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Security BearerAuth
// @Router /tasks/{id} [get]
func (h *TaskHandler) GetTask(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		BadRequest(c, "Task ID is required")
		return
	}

	var task models.Task
	if err := h.DB.First(&task, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "Task not found")
			return
		}
		InternalServerError(c, err)
		return
	}

	c.JSON(http.StatusOK, task)
}

// ListTasks godoc
// @Summary List all tasks
// @Description Retrieves all tasks. Requires JWT access token.
// @Tags Tasks
// @Produce json
// @Success 200 {array} models.Task
// @Failure 401 {object} map[string]string
// @Security BearerAuth
// @Router /tasks [get]
func (h *TaskHandler) ListTasks(c *gin.Context) {
	var tasks []models.Task
	if err := h.DB.Find(&tasks).Error; err != nil {
		InternalServerError(c, err)
		return
	}

	c.JSON(http.StatusOK, tasks)
}

// UpdateTask godoc
// @Summary Update a task
// @Description Updates an existing task. Requires JWT access token.
// @Tags Tasks
// @Accept json
// @Produce json
// @Param id path string true "Task ID"
// @Param task body models.UpdateTaskRequest true "Task fields to update"
// @Success 200 {object} models.Task
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Security BearerAuth
// @Router /tasks/{id} [put]
func (h *TaskHandler) UpdateTask(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		BadRequest(c, "Task ID is required")
		return
	}

	var task models.Task
	if err := h.DB.First(&task, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "Task not found")
			return
		}
		InternalServerError(c, err)
		return
	}

	var input models.UpdateTaskRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		BadRequest(c, "Invalid request body: "+err.Error())
		return
	}

	// Update only provided fields
	if input.Title != "" {
		task.Title = input.Title
	}
	if input.Description != "" {
		task.Description = input.Description
	}
	if input.Status != "" {
		task.Status = input.Status
	}

	if err := h.DB.Save(&task).Error; err != nil {
		InternalServerError(c, err)
		return
	}

	c.JSON(http.StatusOK, task)
}

// DeleteTask godoc
// @Summary Delete a task
// @Description Deletes a task by ID. Requires JWT access token.
// @Tags Tasks
// @Param id path string true "Task ID"
// @Success 204 {string} string "No Content"
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Security BearerAuth
// @Router /tasks/{id} [delete]
func (h *TaskHandler) DeleteTask(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		BadRequest(c, "Task ID is required")
		return
	}

	result := h.DB.Delete(&models.Task{}, "id = ?", id)
	if result.Error != nil {
		InternalServerError(c, result.Error)
		return
	}

	if result.RowsAffected == 0 {
		NotFound(c, "Task not found")
		return
	}

	c.Status(http.StatusNoContent)
}
