package main

import (
	"fmt"
	"go_auth/internal/adapters/http/fiber"
	"go_auth/internal/adapters/persistence/postgres"
	"go_auth/internal/adapters/persistence/postgres/pgerr"
	"log"
)

func main() {
	dbCfg, err := postgres.LoadPostgresConfig()
	if err != nil {
		log.Fatalf("FAILED [DB_CONFIG]: %v", err)
	}

	db, err := postgres.NewPostgresConnection(dbCfg)
	if err != nil {
		log.Fatalf("FAILED [DB_CONN]: %v", err)
	}

	if err := postgres.AutoMigrate(db); err != nil {
		mErr := pgerr.NewMigrationErr(err)
		log.Fatalf("FAILED [DB_MIGRATION]: %v", mErr.Error())
	}

	deps, err := fiber.InitDeps(db)
	if err != nil {
		log.Fatalf("FAILED [DEPENDENCIES]: %v", err)
	}

	fiberCfg, err := fiber.NewFiberConfig()
	if err != nil {
		log.Fatalf("FAILED [APP_CONFIG]: %v", err)
	}

	app := fiber.NewFiberApp(deps, fiberCfg)

	log.Printf("Fiber server running on :%d\n", fiberCfg.Port())
	if err := app.Listen(fmt.Sprintf(":%d", fiberCfg.Port())); err != nil {
		log.Fatalf("FAILED [RUNTIME]: %v", err)
	}
}
