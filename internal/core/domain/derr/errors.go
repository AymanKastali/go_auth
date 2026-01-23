package derr

// ErrorCode defines the high-level category of the domain failure.
// This allows the application layer to map domain errors to appropriate HTTP/GRPC codes.
type ErrorCode string

const (
	// CodeValidation: Inputs don't meet basic constraints (e.g., malformed email).
	// Maps to 400 Bad Request.
	CodeValidation ErrorCode = "VALIDATION_FAILED"

	// CodeBusinessRule: The state transition is illegal (e.g., rotating a revoked token).
	// Maps to 422 Unprocessable Entity.
	CodeBusinessRule ErrorCode = "BUSINESS_RULE_VIOLATION"

	// CodeConflict: The request conflicts with current state (e.g., email already exists).
	// Maps to 409 Conflict.
	CodeConflict ErrorCode = "CONFLICT"

	// CodeNotFound: The requested entity does not exist.
	// Maps to 404 Not Found.
	CodeNotFound ErrorCode = "NOT_FOUND"

	// CodeForbidden: Security policy violation (e.g., device doesn't belong to user).
	// Maps to 403 Forbidden.
	CodeForbidden ErrorCode = "FORBIDDEN"
)

// DomainError is the interface all custom error structs in this package implement.
// By using an interface, the Application Layer can use errors.As() to extract
// the ErrorCode and the specific struct metadata.
type DomainError interface {
	error
	Code() ErrorCode
}
