package main

import (
	"go_auth/src/infra/persistence/postgres"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"gorm.io/gorm"
)

func main() {
	// Wait for Postgres to be ready
	var db *gorm.DB
	var err error
	db, err = postgres.NewPostgresConnection()

	if err != nil {
		log.Fatal("Could not connect to Postgres:", err)
	}

	postgres.AutoMigrate(db)

	// Fiber App
	app := fiber.New()

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New())

	// Health endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	log.Println("Fiber server running on :8080")
	if err := app.Listen(":8080"); err != nil {
		log.Fatal(err)
	}
}
