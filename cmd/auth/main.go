package main

import "log"

// @title Auth Service API
// @version 1.0
// @description Authentication service using Hexagonal Architecture and Fiber v3.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.email support@example.com

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func main() {
	c, err := newContainer()
	if err != nil {
		log.Fatalf("failed to start: %v\n", err)
	}
	c.run()
}
