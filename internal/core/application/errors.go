package application

import "go_auth/internal/core/pkg/err"

// ---------------------------------------------------------
// Application Sentinel Registry
// ---------------------------------------------------------

var (
	// --- Infrastructure Shielding ---
	// This is the "Safety Net". Use this to wrap database crashes,
	// network timeouts, or library panics to avoid leaking technical details.
	ErrInternal = err.New(err.CodeInternal, "an unexpected internal error occurred")

	// --- Process & Orchestration ---
	// Use this when a repository lookup returns nil but the
	// use case requires that resource to proceed with the next step.
	ErrResourceNotFound = err.New(err.CodeNotFound, "the requested resource could not be found")

	// Use this when the request payload is syntactically valid (JSON is ok)
	// but is missing orchestration metadata (e.g., missing a required Context ID).
	ErrMalformedRequest = err.New(err.CodeValidation, "the request is missing required orchestration data")

	// --- Security Boundaries ---
	// Use this when the user is authenticated, but the application orchestrator
	// refuses to execute the flow for this specific identity/context.
	ErrAccessDenied = err.New(err.CodeForbidden, "access to this operation is denied")

	// --- Concurrency & System State ---
	// Use this when a race condition is detected at the orchestration level
	// (e.g., a "late duplicate" caught by a database constraint).
	ErrConflict = err.New(err.CodeConflict, "the operation conflicted with the current state of the system")
)
