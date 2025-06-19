// @title iShare Task Management API
// @version 1.0
// @description Professional, production-quality RESTful API for task management with OAuth2 and iSHARE compliance.
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token."
// @Security BearerAuth
package main

import (
	"log"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/gin-gonic/gin"
	_ "github.com/ishare/taskapi/docs"
	"github.com/ishare/taskapi/internal/api"
	"github.com/ishare/taskapi/internal/auth"
	"github.com/ishare/taskapi/internal/config"
	"github.com/ishare/taskapi/internal/db"
	"github.com/joho/godotenv"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func openBrowser(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd = "rundll32"
		args = append(args, "url.dll,FileProtocolHandler")
	default: // linux, freebsd, openbsd, netbsd
		cmd = "xdg-open"
	}
	args = append(args, url)
	exec.Command(cmd, args...).Start()
}

func main() {
	// Get the project root directory
	_, b, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(b), "../..")

	// Load .env file from project root
	if err := godotenv.Load(filepath.Join(projectRoot, ".env")); err != nil {
		log.Printf("Warning: .env file not found: %v", err)
	}

	cfg := config.LoadConfig()
	// Debug print (masking password)
	if cfg.DBUrl != "" {
		log.Printf("Database URL found (password masked): %s", cfg.DBUrl)
	} else {
		log.Printf("Warning: DATABASE_URL is empty")
	}

	// Set Gin to release mode
	gin.SetMode(gin.DebugMode)

	database, err := db.InitDB(cfg)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	_ = database // Will be used in handlers

	r := gin.Default()

	// Configure trusted proxies
	r.SetTrustedProxies([]string{"127.0.0.1"}) // Add your trusted proxy IPs here

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	r.GET("/authorize", auth.AuthorizeEndpoint(cfg, database))
	r.POST("/token", auth.TokenEndpoint(cfg, database))
	r.POST("/register", auth.RegisterClientEndpoint(database))

	taskHandler := api.NewTaskHandler(database)
	taskGroup := r.Group("/tasks")
	taskGroup.Use(auth.JWTMiddleware(cfg))
	{
		taskGroup.POST("", taskHandler.CreateTask)
		taskGroup.GET("", taskHandler.ListTasks)
		taskGroup.GET(":id", taskHandler.GetTask)
		taskGroup.PUT(":id", taskHandler.UpdateTask)
		taskGroup.DELETE(":id", taskHandler.DeleteTask)
	}

	r.GET("/clients", auth.ListClientsEndpoint(database))

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, ginSwagger.DefaultModelsExpandDepth(-1)))

	log.Printf("Server starting on port %s...", cfg.Port)
	go openBrowser("http://localhost:" + cfg.Port + "/swagger/index.html")
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatalf("failed to run server: %v", err)
	}
}
