package db

import (
	"github.com/ishare/taskapi/internal/config"
	"github.com/ishare/taskapi/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func InitDB(cfg *config.Config) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(cfg.DBUrl), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	// Auto-migrate the Task and Client models
	db.Migrator().AutoMigrate(&models.Task{}, &models.Client{})
	return db, nil
}
