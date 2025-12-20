package handlers

import (
	"go_auth/src/application/dto"
	"go_auth/src/application/ports/services"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
	value_objects "go_auth/src/domain/value_objects"

	"github.com/google/uuid"
)

type LoginHandler struct {
	userRepository       repositories.UserRepositoryPort
	membershipRepository repositories.MembershipRepositoryPort
	passwordHasher       services.HashPasswordPort
	tokenService         services.TokenServicePort
	emailFactory         factories.EmailFactory
}

func NewLoginHandler(
	userRepository repositories.UserRepositoryPort,
	membershipRepository repositories.MembershipRepositoryPort,
	passwordHasher services.HashPasswordPort,
	tokenService services.TokenServicePort,
	emailFactory factories.EmailFactory,
) *LoginHandler {
	return &LoginHandler{
		userRepository:       userRepository,
		membershipRepository: membershipRepository,
		passwordHasher:       passwordHasher,
		tokenService:         tokenService,
		emailFactory:         emailFactory,
	}
}

func (h *LoginHandler) Execute(
	email string,
	password string,
	organizationID *uuid.UUID,
) (*dto.AuthResponse, error) {

	// --- Parse and validate email ---
	emailVO, err := h.emailFactory.New(email)
	if err != nil {
		return nil, err
	}

	// --- Fetch user ---
	user, err := h.userRepository.GetByEmail(emailVO)
	if err != nil || user == nil {
		return nil, errors.ErrInvalidCredentials
	}

	// --- Validate password ---
	if !h.passwordHasher.Compare(password, user.PasswordHash.Value) {
		return nil, errors.ErrInvalidCredentials
	}

	// --- Wrap organizationID into value object ---
	var orgID value_objects.OrganizationID
	if organizationID != nil {
		orgID = value_objects.OrganizationID{
			Value: *organizationID,
		}
	}

	// --- Check membership if orgID is provided ---
	var roles []string
	if !orgID.IsZero() {
		membership, err := h.membershipRepository.GetByUserAndOrganization(
			user.ID,
			orgID,
		)
		if err != nil {
			return nil, err
		}
		if membership == nil {
			return nil, errors.ErrUserNotMemberOfOrganization
		}

		// Extract roles from membership
		if membership.Role != "" {
			roles = []string{string(membership.Role)}
		}
	}

	// --- Convert IDs to strings for JWT / token service ---
	userIDStr := user.ID.Value.String()

	var orgIDStr *string
	if !orgID.IsZero() {
		s := orgID.Value.String()
		orgIDStr = &s
	}

	// --- Issue tokens ---
	accessToken, err := h.tokenService.IssueAccessToken(userIDStr, orgIDStr, roles)
	if err != nil {
		return nil, err
	}

	refreshToken, err := h.tokenService.IssueRefreshToken(userIDStr)
	if err != nil {
		return nil, err
	}

	// --- Return response ---
	return &dto.AuthResponse{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
	}, nil
}
