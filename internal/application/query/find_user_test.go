package query

import (
	"context"
	"testing"
	"time"

	"go_auth/internal/application"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testReadModel = application.UserReadModel{
	ID:           "user-001",
	Email:        "test@example.com",
	IsActive:     true,
	Roles:        []string{"member"},
	RegisteredAt: time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
	UpdatedAt:    time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
}

func TestFindUserByEmailHandler(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		h := NewFindUserByEmailHandler(&stubUserQueryPort{findByEmailResult: testReadModel})

		resp, err := h.Handle(context.Background(), "test@example.com")
		require.NoError(t, err)
		assert.Equal(t, "user-001", resp.ID)
		assert.Equal(t, "test@example.com", resp.Email)
	})

	t.Run("empty_email", func(t *testing.T) {
		h := NewFindUserByEmailHandler(&stubUserQueryPort{})
		_, err := h.Handle(context.Background(), "")
		assert.ErrorIs(t, err, application.ErrResourceNotFound)
	})

	t.Run("not_found", func(t *testing.T) {
		h := NewFindUserByEmailHandler(&stubUserQueryPort{findByEmailErr: application.ErrResourceNotFound})
		_, err := h.Handle(context.Background(), "miss@example.com")
		assert.ErrorIs(t, err, application.ErrResourceNotFound)
	})
}

func TestGetUserByIDHandler(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		h := NewGetUserByIDHandler(&stubUserQueryPort{findByIDResult: testReadModel})

		resp, err := h.Handle(context.Background(), "user-001")
		require.NoError(t, err)
		assert.Equal(t, "user-001", resp.ID)
	})

	t.Run("empty_id", func(t *testing.T) {
		h := NewGetUserByIDHandler(&stubUserQueryPort{})
		_, err := h.Handle(context.Background(), "")
		assert.ErrorIs(t, err, application.ErrResourceNotFound)
	})

	t.Run("not_found", func(t *testing.T) {
		h := NewGetUserByIDHandler(&stubUserQueryPort{findByIDErr: application.ErrResourceNotFound})
		_, err := h.Handle(context.Background(), "user-999")
		assert.ErrorIs(t, err, application.ErrResourceNotFound)
	})
}

func TestGetMeHandler(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		h := NewGetMeHandler(&stubUserQueryPort{findByIDResult: testReadModel})

		resp, err := h.Handle(context.Background(), "user-001")
		require.NoError(t, err)
		assert.Equal(t, "user-001", resp.ID)
	})

	t.Run("empty_id", func(t *testing.T) {
		h := NewGetMeHandler(&stubUserQueryPort{})
		_, err := h.Handle(context.Background(), "")
		assert.ErrorIs(t, err, application.ErrResourceNotFound)
	})

	t.Run("not_found", func(t *testing.T) {
		h := NewGetMeHandler(&stubUserQueryPort{findByIDErr: application.ErrResourceNotFound})
		_, err := h.Handle(context.Background(), "user-999")
		assert.ErrorIs(t, err, application.ErrResourceNotFound)
	})
}
