package main

import (
	"go_auth/src/bootstrap"
	"log"
)

func main() {
	app, err := bootstrap.NewApp()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Fiber server running on :8080")
	log.Fatal(app.Listen(":8080"))
}
