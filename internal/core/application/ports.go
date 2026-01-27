package application

import (
	"context"
)

// IRegisterUseCase defines the boundary for creating a new user.
type IRegisterUseCase interface {
	// Execute orchestrates the registration process.
	// It takes a Command (DTO) and returns an error if the process fails.
	Execute(ctx context.Context, cmd RegisterUserCommand) (RegisterUserResponse, error)
}

// ILoginUserUseCase defines the boundary for user authentication.
type ILoginUserUseCase interface {
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
type ISeedSuperAdmin interface {
	Execute(ctx context.Context, cmd RegisterUserCommand) error
}
