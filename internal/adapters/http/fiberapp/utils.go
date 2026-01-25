package fiberapp

import (
	"strings"

	"github.com/go-playground/validator/v10"
)

// Go Validator
var validate = validator.New()

func Validate(s any) error { return validate.Struct(s) }

// Bearer Token
func ExtractToken(authHeader string) string {
	if authHeader == "" {
		return ""
	}

	// Standard Bearer token format: "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		// If it doesn't follow Bearer format, return as is or return empty
		// depending on your strictness. Here we stay strict:
		return ""
	}

	return parts[1]
}
