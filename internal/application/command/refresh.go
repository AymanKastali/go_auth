package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IRefreshTokenHandler interface {
	Handle(ctx context.Context, cmd RefreshTokenCommand) (LoginResponse, error)
}

type refreshTokenHandler struct {
	userRepo    domain.IUserRepository
	sessionRepo domain.ISessionRepository
	roleRepo    domain.IRoleRepository
	refresher   domain.IRefreshSession
	granter     domain.IGrantAccess
	tokenSvc    domain.ITokenService
	clock       domain.IClock
	dispatcher  IEventDispatcher
}

func NewRefreshTokenHandler(
	userRepo domain.IUserRepository,
	sessionRepo domain.ISessionRepository,
	roleRepo domain.IRoleRepository,
	refresher domain.IRefreshSession,
	granter domain.IGrantAccess,
	tokenSvc domain.ITokenService,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IRefreshTokenHandler {
	return &refreshTokenHandler{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		roleRepo:    roleRepo,
		refresher:   refresher,
		granter:     granter,
		tokenSvc:    tokenSvc,
		clock:       clock,
		dispatcher:  dispatcher,
	}
}

func (h *refreshTokenHandler) Handle(ctx context.Context, cmd RefreshTokenCommand) (LoginResponse, error) {
	logger := application.GetLogger(ctx).With(slog.String("handler", "RefreshToken"))

	if cmd.RefreshToken == "" {
		return ZeroLoginResponse, domain.ErrTokenInvalid
	}

	fp, err := domain.NewDeviceFingerprint(cmd.Fingerprint)
	if err != nil {
		return ZeroLoginResponse, err
	}

	now := h.clock.Now()

	hashed, err := h.tokenSvc.HashSessionToken(cmd.RefreshToken)
	if err != nil {
		logger.Error("token_hash_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	session, err := h.sessionRepo.FindByToken(ctx, hashed)
	if err != nil {
		logger.Error("session_lookup_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	foundByPrevious := false
	if session == nil {
		session, err = h.sessionRepo.FindByPreviousToken(ctx, hashed)
		if err != nil {
			logger.Error("previous_token_lookup_failed", slog.Any("error", err))
			return ZeroLoginResponse, err
		}
		if session == nil {
			return ZeroLoginResponse, domain.ErrSessionNotFound
		}
		foundByPrevious = true
	}

	user, err := h.userRepo.FindByID(ctx, session.UserID())
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}
	if user == nil || user.IsDeleted() || !user.IsActive() {
		return ZeroLoginResponse, domain.ErrUserInactive
	}

	newRawToken, err := h.refresher.Refresh(session, foundByPrevious, fp, now)
	if err != nil {
		if session.IsRevoked() {
			if saveErr := h.sessionRepo.Save(ctx, session); saveErr != nil {
				logger.Error("revoked_session_save_failed", slog.Any("error", saveErr))
			}
			h.dispatcher.Dispatch(ctx, session.CollectEvents())
		}
		logger.Warn("refresh_session_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	roles, err := application.LoadRoles(ctx, h.roleRepo, user.Roles())
	if err != nil {
		logger.Error("role_loading_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	accessToken, accessExpiry, err := h.granter.Grant(user, session.ID(), roles, now)
	if err != nil {
		logger.Error("access_grant_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	if err := h.sessionRepo.Save(ctx, session); err != nil {
		logger.Error("session_save_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	h.dispatcher.Dispatch(ctx, session.CollectEvents())

	logger.Info("refresh_token_success",
		slog.String("user_id", user.ID().String()),
		slog.String("session_id", session.ID().String()),
	)

	return LoginResponse{
		AccessToken:        accessToken.String(),
		AccessTokenExpiry:  accessExpiry.String(),
		RefreshToken:       newRawToken,
		RefreshTokenExpiry: session.Expiry().Time().String(),
	}, nil
}
