package application

import (
	"context"

	"go_auth/internal/core/domain"
)

type ITransactionManager interface {
	WithTransaction(ctx context.Context, fn func(txCtx context.Context) error) error
}

type IEventDispatcher interface {
	Dispatch(ctx context.Context, events []domain.DomainEvent)
}

type IEmailService interface {
	// SendResetLink sends the raw recovery token to the user's email
	SendResetLink(toEmail string, rawToken string) error
}

// IRegisterUseCase defines the boundary for creating a new user.
type IRegisterUseCase interface {
	// Execute orchestrates the registration process.
	// It takes a Command (DTO) and returns an error if the process fails.
	Execute(ctx context.Context, cmd RegisterUserCommand) (RegisterUserResponse, error)
}

// ILoginUseCase defines the boundary for user authentication.
type ILoginUseCase interface {
	// Execute verifies credentials and returns the response DTO containing the RawToken.
	Execute(ctx context.Context, cmd LoginCommand) (LoginResponse, error)
}

// IRefreshTokenUseCase handles exchanging a valid session for a new access token.
type IRefreshTokenUseCase interface {
	Execute(ctx context.Context, cmd RefreshTokenCommand) (LoginResponse, error)
}

// IValidateAccessUseCase defines the boundary for session verification (Middleware logic).
type IValidateAccessUseCase interface {
	// Execute validates the current session state.
	Execute(ctx context.Context, query ValidateAccessQuery) (ValidateAccessResponse, error)
}

// ILogoutUseCase handles the revocation of a specific session.
type ILogoutUseCase interface {
	Execute(ctx context.Context, cmd LogoutCommand) error
}

// ISeedSuperAdmin handles the creation of the super admin user when bootstrap the app.
type ISeedSuperAdminUseCase interface {
	Execute(ctx context.Context, cmd RegisterUserCommand) error
}

type IFindUserByEmailUseCase interface {
	Execute(ctx context.Context, email string) (UserResponse, error)
}

type IGetUserByIDUseCase interface {
	Execute(ctx context.Context, id string) (UserResponse, error)
}

type IGetMeUseCase interface {
	Execute(ctx context.Context, id string) (UserResponse, error)
}
type IUpdateMeUseCase interface {
	Execute(ctx context.Context, cmd UpdateMeCommand) error
}

type IChangePasswordUseCase interface {
	Execute(ctx context.Context, cmd ChangePasswordCommand) error
}

type IResetPasswordUseCase interface {
	Execute(ctx context.Context, cmd ResetPasswordCommand) error
}

type IForgotPasswordUseCase interface {
	Execute(ctx context.Context, cmd ForgotPasswordCommand) error
}
