package application

import (
	"context"

	"go_auth/internal/domain"
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
	// SendActivationLink sends the raw activation token to the user's email
	SendActivationLink(toEmail string, rawToken string) error
}

type IUserQueryPort interface {
	FindByID(ctx context.Context, id string) (UserReadModel, error)
	FindByEmail(ctx context.Context, email string) (UserReadModel, error)
	FindAll(ctx context.Context, offset, limit int) ([]UserReadModel, int64, error)
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
	Execute(ctx context.Context, email string) (UserReadModel, error)
}

type IGetUserByIDUseCase interface {
	Execute(ctx context.Context, id string) (UserReadModel, error)
}

type IGetMeUseCase interface {
	Execute(ctx context.Context, id string) (UserReadModel, error)
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

// IGetPublicPoliciesUseCase returns the publicly visible policy configuration.
type IGetPublicPoliciesUseCase interface {
	Execute(ctx context.Context) (PublicPoliciesResponse, error)
}

// RoleSeedDefinition represents a role with its permissions to be seeded.
type RoleSeedDefinition struct {
	Name        string
	Description string
	Permissions []string
}

// IConfirmActivationUseCase defines the boundary for confirming user activation.
type IConfirmActivationUseCase interface {
	Execute(ctx context.Context, cmd ConfirmActivationCommand) error
}

// IResendActivationUseCase defines the boundary for resending activation emails.
type IResendActivationUseCase interface {
	Execute(ctx context.Context, cmd ResendActivationCommand) error
}

// IHealthChecker defines the boundary for checking infrastructure health.
type IHealthChecker interface {
	Ping(ctx context.Context) error
}

// IRoleSeedLoader loads role seed definitions from an external source.
type IRoleSeedLoader interface {
	Load() ([]RoleSeedDefinition, error)
}

// ISeedRolesUseCase handles seeding roles from a YAML file.
type ISeedRolesUseCase interface {
	Execute(ctx context.Context) error
}

// --- Role Management Use Cases ---

type IListRolesUseCase interface {
	Execute(ctx context.Context) ([]RoleReadModel, error)
}

type IGetRoleUseCase interface {
	Execute(ctx context.Context, id string) (RoleReadModel, error)
}

type ICreateRoleUseCase interface {
	Execute(ctx context.Context, cmd CreateRoleCommand) (RoleReadModel, error)
}

type IAssignPermissionUseCase interface {
	Execute(ctx context.Context, cmd AssignPermissionCommand) error
}

type IRevokePermissionUseCase interface {
	Execute(ctx context.Context, cmd RevokePermissionCommand) error
}

// --- Admin User Management Use Cases ---

type IListUsersUseCase interface {
	Execute(ctx context.Context, query ListUsersQuery) (ListUsersResponse, error)
}

type IAssignUserRoleUseCase interface {
	Execute(ctx context.Context, cmd AssignUserRoleCommand) error
}

type IRevokeUserRoleUseCase interface {
	Execute(ctx context.Context, cmd RevokeUserRoleCommand) error
}

type IAdminActivateUserUseCase interface {
	Execute(ctx context.Context, id string) error
}

type IAdminDeactivateUserUseCase interface {
	Execute(ctx context.Context, id string) error
}

type IAdminDeleteUserUseCase interface {
	Execute(ctx context.Context, id string) error
}
