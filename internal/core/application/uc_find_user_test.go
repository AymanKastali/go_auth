package application

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testReadModel = UserReadModel{
	ID:        "user-001",
	Email:     "test@example.com",
	IsActive:  true,
	Roles:     []string{"member"},
	RegisteredAt: time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
	UpdatedAt: time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
}

func TestFindUserByEmailUseCase(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		uc := NewFindUserByEmailUseCase(&stubUserQueryPort{findByEmailResult: testReadModel})

		resp, err := uc.Execute(context.Background(), "test@example.com")
		require.NoError(t, err)
		assert.Equal(t, "user-001", resp.ID)
		assert.Equal(t, "test@example.com", resp.Email)
	})

	t.Run("empty_email", func(t *testing.T) {
		uc := NewFindUserByEmailUseCase(&stubUserQueryPort{})
		_, err := uc.Execute(context.Background(), "")
		assert.ErrorIs(t, err, ErrResourceNotFound)
	})

	t.Run("not_found", func(t *testing.T) {
		uc := NewFindUserByEmailUseCase(&stubUserQueryPort{findByEmailErr: ErrResourceNotFound})
		_, err := uc.Execute(context.Background(), "miss@example.com")
		assert.ErrorIs(t, err, ErrResourceNotFound)
	})
}

func TestGetUserByIDUseCase(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		uc := NewGetUserByIDUseCase(&stubUserQueryPort{findByIDResult: testReadModel})

		resp, err := uc.Execute(context.Background(), "user-001")
		require.NoError(t, err)
		assert.Equal(t, "user-001", resp.ID)
	})

	t.Run("empty_id", func(t *testing.T) {
		uc := NewGetUserByIDUseCase(&stubUserQueryPort{})
		_, err := uc.Execute(context.Background(), "")
		assert.ErrorIs(t, err, ErrResourceNotFound)
	})

	t.Run("not_found", func(t *testing.T) {
		uc := NewGetUserByIDUseCase(&stubUserQueryPort{findByIDErr: ErrResourceNotFound})
		_, err := uc.Execute(context.Background(), "user-999")
		assert.ErrorIs(t, err, ErrResourceNotFound)
	})
}

func TestGetMeUseCase(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		uc := NewGetMeUseCase(&stubUserQueryPort{findByIDResult: testReadModel})

		resp, err := uc.Execute(context.Background(), "user-001")
		require.NoError(t, err)
		assert.Equal(t, "user-001", resp.ID)
	})

	t.Run("empty_id", func(t *testing.T) {
		uc := NewGetMeUseCase(&stubUserQueryPort{})
		_, err := uc.Execute(context.Background(), "")
		assert.ErrorIs(t, err, ErrResourceNotFound)
	})

	t.Run("not_found", func(t *testing.T) {
		uc := NewGetMeUseCase(&stubUserQueryPort{findByIDErr: ErrResourceNotFound})
		_, err := uc.Execute(context.Background(), "user-999")
		assert.ErrorIs(t, err, ErrResourceNotFound)
	})
}
