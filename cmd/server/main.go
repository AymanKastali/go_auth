package main

import "go_auth/internal/bootstrap"

func main() {
	c := bootstrap.NewFiberPostgresContainer()
	c.Run()
}
