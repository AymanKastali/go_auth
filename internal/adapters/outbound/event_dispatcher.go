package outbound

import (
	"context"
	"log/slog"

	"go_auth/internal/application/command"
	"go_auth/internal/domain"
)

// LoggingEventDispatcher logs each dispatched domain event. It serves as the
// default adapter while no real event handlers are wired.
type LoggingEventDispatcher struct {
	logger *slog.Logger
}

func NewLoggingEventDispatcher(logger *slog.Logger) command.IEventDispatcher {
	return &LoggingEventDispatcher{logger: logger}
}

func (d *LoggingEventDispatcher) Dispatch(ctx context.Context, events []domain.DomainEvent) {
	for _, e := range events {
		d.logger.Info("domain_event",
			slog.String("event", e.EventName()),
			slog.String("aggregate_id", e.AggregateID()),
			slog.String("occurred_at", e.OccurredAt().String()),
		)
	}
}
