package application

import "context"

// IHealthChecker defines the boundary for checking infrastructure health.
type IHealthChecker interface {
	Ping(ctx context.Context) error
}

// IUserQueryPort is the read-side port for user projections.
type IUserQueryPort interface {
	FindByID(ctx context.Context, id string) (UserReadModel, error)
	FindByEmail(ctx context.Context, email string) (UserReadModel, error)
	FindAll(ctx context.Context, offset, limit int) ([]UserReadModel, int64, error)
}

// IRoleQueryPort is the read-side port for role projections.
type IRoleQueryPort interface {
	FindByID(ctx context.Context, id string) (RoleReadModel, error)
	FindAll(ctx context.Context) ([]RoleReadModel, error)
}
