package main

import (
	"fmt"
	"go_auth/internal/adapters/http/fiber"
)

func main() {
	deps, err := fiber.InitDeps()
	if err != nil {
		fmt.Println(err)
	}

	app := fiber.NewFiberApp(deps)

	fmt.Println("Fiber server running on :8080")
	fmt.Println(app.Listen(":8080"))
}
