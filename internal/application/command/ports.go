package command

import (
	"context"

	"go_auth/internal/domain"
)

// ITransactionManager orchestrates transactional boundaries.
type ITransactionManager interface {
	WithTransaction(ctx context.Context, fn func(txCtx context.Context) error) error
}

// IEventDispatcher publishes domain events after handler completion.
type IEventDispatcher interface {
	Dispatch(ctx context.Context, events []domain.DomainEvent)
}

// IEmailService handles outbound email delivery.
type IEmailService interface {
	SendResetLink(toEmail string, rawToken string) error
	SendActivationLink(toEmail string, rawToken string) error
}

// IRoleSeedLoader loads role seed definitions from an external source.
type IRoleSeedLoader interface {
	Load() ([]RoleSeedDefinition, error)
}
