package bootstrap

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func createFiberApp() *fiber.App {
	app := fiber.New()

	app.Use(recover.New())
	app.Use(logger.New())

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	return app
}

func NewApp() (*fiber.App, error) {
	app := createFiberApp()

	db, err := newDatabase()
	if err != nil {
		return nil, err
	}

	rdb, err := newRedis()
	if err != nil {
		fmt.Println("rdb: ", rdb)
		return nil, err
	}

	deps, err := wireDependencies(db)
	if err != nil {
		return nil, err
	}

	registerRoutes(app, deps)

	return app, nil
}
