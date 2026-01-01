package main

import (
	"fmt"
	"go_auth/internal/adapters/http/fiber"
	"go_auth/internal/adapters/persistence/postgres"
	"log"
)

func main() {
	dbCfg, err := postgres.LoadPostgresConfig()
	if err != nil {
		log.Fatalf("failed to load database config: %v", err)
	}

	db, err := postgres.NewPostgresConnection(dbCfg)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	postgres.AutoMigrate(db)

	deps, err := fiber.InitDeps(db)
	if err != nil {
		fmt.Println(err)
	}

	fiberCfg, err := fiber.NewFiberConfig()
	if err != nil {
		fmt.Println(err)
	}

	app := fiber.NewFiberApp(deps, fiberCfg)

	fmt.Printf("Fiber server running on :%d", fiberCfg.Port())
	log.Fatal(app.Listen(fmt.Sprintf(":%d", fiberCfg.Port())))
}
