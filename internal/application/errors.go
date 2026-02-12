package application

import "go_auth/internal/domain"

// ---------------------------------------------------------
// Application Sentinel Registry
// ---------------------------------------------------------

var (
	// ErrUnauthorized is raised when the Application Context is missing
	// a valid UserID/SessionID in a protected handler.
	ErrUnauthorized = domain.NewError(domain.KindUnauthorized, "authentication is required to access this resource")

	// --- Infrastructure Shielding ---
	// This is the "Safety Net". Use this to wrap database crashes,
	// network timeouts, or library panics to avoid leaking technical details.
	ErrInternal = domain.NewError(domain.KindInternal, "an unexpected internal error occurred")

	// --- Process & Orchestration ---
	// Use this when a repository lookup returns nil but the
	// handler requires that resource to proceed with the next step.
	ErrResourceNotFound = domain.NewError(domain.KindNotFound, "the requested resource could not be found")

	// --- Security Boundaries ---
	// Use this when the user is authenticated, but the application orchestrator
	// refuses to execute the flow for this specific identity/context.
	ErrAccessDenied = domain.NewError(domain.KindForbidden, "access to this operation is denied")

	// --- Concurrency & System State ---
	// Use this when a race condition is detected at the orchestration level
	// (e.g., a "late duplicate" caught by a database constraint).
	ErrConflict = domain.NewError(domain.KindConflict, "the operation conflicted with the current state of the system")
)
