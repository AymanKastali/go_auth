package application

import (
	"context"
	"testing"

	"go_auth/internal/core/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindUserByEmailUseCase(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		uc := NewFindUserByEmailUseCase(&stubAppUserRepository{findByEmailResult: user})

		resp, err := uc.Execute(context.Background(), "test@example.com")
		require.NoError(t, err)
		assert.Equal(t, "user-001", resp.ID)
		assert.Equal(t, "test@example.com", resp.Email)
	})

	t.Run("invalid_email", func(t *testing.T) {
		uc := NewFindUserByEmailUseCase(&stubAppUserRepository{})
		_, err := uc.Execute(context.Background(), "bad")
		assert.ErrorIs(t, err, domain.ErrUserEmailInvalid)
	})

	t.Run("not_found", func(t *testing.T) {
		uc := NewFindUserByEmailUseCase(&stubAppUserRepository{findByEmailResult: nil})
		_, err := uc.Execute(context.Background(), "miss@example.com")
		assert.ErrorIs(t, err, ErrResourceNotFound)
	})
}

func TestGetUserByIDUseCase(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		uc := NewGetUserByIDUseCase(&stubAppUserRepository{findByIDResult: user})

		resp, err := uc.Execute(context.Background(), "user-001")
		require.NoError(t, err)
		assert.Equal(t, "user-001", resp.ID)
	})

	t.Run("invalid_id", func(t *testing.T) {
		uc := NewGetUserByIDUseCase(&stubAppUserRepository{})
		_, err := uc.Execute(context.Background(), "")
		assert.ErrorIs(t, err, domain.ErrUserIDRequired)
	})

	t.Run("not_found", func(t *testing.T) {
		uc := NewGetUserByIDUseCase(&stubAppUserRepository{findByIDResult: nil})
		_, err := uc.Execute(context.Background(), "user-999")
		assert.ErrorIs(t, err, ErrResourceNotFound)
	})
}

func TestGetMeUseCase(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		uc := NewGetMeUseCase(&stubAppUserRepository{findByIDResult: user})

		resp, err := uc.Execute(context.Background(), "user-001")
		require.NoError(t, err)
		assert.Equal(t, "user-001", resp.ID)
	})

	t.Run("invalid_id", func(t *testing.T) {
		uc := NewGetMeUseCase(&stubAppUserRepository{})
		_, err := uc.Execute(context.Background(), "")
		assert.ErrorIs(t, err, domain.ErrUserIDRequired)
	})

	t.Run("not_found", func(t *testing.T) {
		uc := NewGetMeUseCase(&stubAppUserRepository{findByIDResult: nil})
		_, err := uc.Execute(context.Background(), "user-999")
		assert.ErrorIs(t, err, ErrResourceNotFound)
	})
}
