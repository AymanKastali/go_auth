package main

import (
	"log/slog"

	"go_auth/internal/adapters"
	"go_auth/internal/adapters/inbound/fiberapp"
	"go_auth/internal/adapters/outbound"
	"go_auth/internal/adapters/outbound/postgres"
	"go_auth/internal/application"
	"go_auth/internal/application/command"

	"github.com/gofiber/fiber/v3"
)

// outboundAdapters holds driven adapter implementations
// (e.g. persistence, email, transactions, event dispatching, queries).
type outboundAdapters struct {
	persistence *postgres.PersistenceFactory
	emailSvc    command.IEmailService
	txManager   command.ITransactionManager
	dispatcher  command.IEventDispatcher
	userQuery   application.IUserQueryPort
	roleQuery   application.IRoleQueryPort
	seedLoader  command.IRoleSeedLoader
}

func newOutboundAdapters(cfg *adapters.Config, logger *slog.Logger) outboundAdapters {
	pf, err := postgres.NewPersistenceFactory(cfg.Database.URL)
	if err != nil {
		panic(err)
	}

	return outboundAdapters{
		persistence: pf,
		emailSvc:    outbound.NewEmailService(cfg.Email),
		txManager:   pf.NewTransactionManager(),
		dispatcher:  outbound.NewLoggingEventDispatcher(logger),
		userQuery:   pf.NewUserQueryAdapter(),
		roleQuery:   pf.NewRoleQueryAdapter(),
		seedLoader:  outbound.NewYAMLRoleSeedLoader(cfg.Seed.RolesFilePath),
	}
}

// fiberControllers groups all Fiber-specific HTTP controllers and middleware.
type fiberControllers struct {
	auth      *fiberapp.AuthController
	user      *fiberapp.UserController
	policy    *fiberapp.PolicyController
	health    *fiberapp.HealthController
	admin     *fiberapp.AdminController
	authGuard fiber.Handler
}

// inboundAdapters holds driving adapter implementations (HTTP controllers).
type inboundAdapters struct {
	fiber fiberControllers
}

func newInboundAdapters(app applicationLayer, out outboundAdapters) inboundAdapters {
	validate := fiberapp.NewValidator()
	authGuard := fiberapp.Protected(app.validate)

	return inboundAdapters{
		fiber: fiberControllers{
			auth: fiberapp.NewAuthController(
				validate,
				app.register,
				app.login,
				app.refresh,
				app.logout,
				app.validate,
				app.forgotPassword,
				app.resetPassword,
				app.confirmActivation,
				app.resendActivation,
				authGuard,
			),
			user: fiberapp.NewUserController(
				validate,
				app.findByEmail,
				app.getByID,
				app.getMe,
				app.updateMe,
				app.changePassword,
			),
			policy:    fiberapp.NewPolicyController(app.publicPolicies),
			health:    fiberapp.NewHealthController(out.persistence),
			admin: fiberapp.NewAdminController(
				validate,
				app.listRoles, app.getRole, app.createRole,
				app.assignPermission, app.revokePermission,
				app.listUsers, app.getByID,
				app.assignUserRole, app.revokeUserRole,
				app.adminActivate, app.adminDeactivate, app.adminDelete,
				app.seedRoles,
			),
			authGuard: authGuard,
		},
	}
}

func newApp(
	cfg adapters.AppConfig,
	h fiberControllers,
	baseLogger *slog.Logger,
) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: fiberapp.NewErrorHandler(),
		AppName:      cfg.Name,
	})

	idGen := outbound.NewULIDGenerator()
	fiberapp.ConfigureMiddlewares(app, baseLogger, idGen)
	fiberapp.SetupRoutes(
		app,
		h.health,
		h.auth,
		h.user,
		h.policy,
		h.admin,
		h.authGuard,
	)
	return app
}
