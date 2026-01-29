package postgres

import (
	"go_auth/internal/core/domain"
	"time"
)

// internal/infrastructure/adapters/postgres/user_mapper.go

func toUserModel(u *domain.User) UserModel {
	roleNames := make([]string, len(u.Roles()))
	for i, r := range u.Roles() {
		roleNames[i] = r.Name()
	}

	sessionModels := make([]SessionModel, len(u.Sessions()))
	for i, s := range u.Sessions() {
		sessionModels[i] = toSessionModel(u.ID().String(), s)
	}

	var deletedAt *time.Time
	if u.DeletedAt() != nil {
		t := u.DeletedAt().Time()
		deletedAt = &t
	}

	return UserModel{
		ID:           u.ID().String(),
		Email:        u.Email().String(),
		PasswordHash: u.HashedPassword().String(),
		IsActive:     u.IsActive(),
		Roles:        roleNames,
		CreatedAt:    u.CreatedAt().Time(),
		UpdatedAt:    u.UpdatedAt().Time(),
		DeletedAt:    deletedAt,
		Sessions:     sessionModels,
	}
}

func toUserDomain(m UserModel) (*domain.User, error) {
	uid := domain.ReconstituteUserID(m.ID)

	email := domain.ReconstituteEmail(m.Email)

	passwordHash := domain.ReconstituteHashedPassword(m.PasswordHash)

	roles := make([]domain.Role, len(m.Roles))
	for i, rName := range m.Roles {
		role := domain.ReconstituteRole(rName)
		roles[i] = role
	}

	sessions := make([]domain.Session, len(m.Sessions))
	for i, sModel := range m.Sessions {
		sDomain, err := toSessionDomain(sModel)
		if err != nil {
			// toSessionDomain already returns a domain error, we just pass it up
			return nil, err
		}
		sessions[i] = sDomain
	}

	var deletedAt *domain.Timepoint
	if m.DeletedAt != nil {
		t := domain.ReconstituteTimepoint(*m.DeletedAt)
		deletedAt = &t
	}

	return domain.ReconstituteUser(
		uid,
		email,
		passwordHash,
		m.IsActive,
		roles,
		sessions,
		domain.ReconstituteTimepoint(m.CreatedAt),
		domain.ReconstituteTimepoint(m.UpdatedAt),
		deletedAt,
	), nil
}

// internal/infrastructure/adapters/postgres/session_mapper.go

func toSessionModel(userID string, s domain.Session) SessionModel {
	var revokedAt *time.Time
	if s.IsRevoked() {
		t := s.RevokedAt().Time()
		revokedAt = &t
	}

	// Access the Value Object from the domain entity
	identity := s.Identity()

	return SessionModel{
		ID:          s.ID().String(),
		UserID:      userID,
		HashedToken: s.HashedToken().String(),
		// Flatten the Value Object into the DB columns
		IPAddress:      identity.IPAddress(),
		UserAgent:      identity.UserAgent(),
		OS:             identity.OS(),
		Browser:        identity.Browser(),
		Model:          identity.Model(),
		AcceptLanguage: identity.Language(),
		IsMobile:       identity.IsMobile(),

		ExpiresAt:    s.ExpiresAt().Time(),
		LastActiveAt: s.LastActiveAt().Time(),
		RevokedAt:    revokedAt,
	}
}

func toSessionDomain(m SessionModel) (domain.Session, error) {
	sid := domain.ReconstituteSessionID(m.ID)

	token := domain.ReconstituteHashedToken(m.HashedToken)

	// 1. Reconstitute the Value Object first
	identity := domain.ReconstituteDeviceIdentity(
		m.IPAddress,
		m.OS,
		m.Browser,
		m.Model,
		m.AcceptLanguage,
		m.UserAgent,
		m.IsMobile,
	)

	var revokedAt *domain.Timepoint
	if m.RevokedAt != nil {
		t := domain.ReconstituteTimepoint(*m.RevokedAt)
		revokedAt = &t
	}

	// 2. Pass the Value Object into the Domain Entity reconstitution
	session := domain.ReconstituteSession(
		sid,
		token,
		identity,
		domain.ReconstituteTimepoint(m.ExpiresAt),
		domain.ReconstituteTimepoint(m.LastActiveAt),
		revokedAt,
	)

	return session, nil
}

// Recovery Token
func toRecoveryTokenModel(t *domain.RecoveryToken) RecoveryTokenModel {
	var usedAt *time.Time
	if t.IsUsed() {
		val := t.UsedAt().Time()
		usedAt = &val
	}

	return RecoveryTokenModel{
		ID:          t.ID().String(),
		UserID:      t.UserID().String(),
		HashedToken: t.HashedToken().String(),
		ExpiresAt:   t.ExpiresAt().Time(),
		CreatedAt:   t.CreatedAt().Time(),
		UsedAt:      usedAt,
	}
}

func toRecoveryTokenDomain(m RecoveryTokenModel) *domain.RecoveryToken {
	// We use our Reconstitutor which handles the Timepoint conversions
	return domain.ReconstituteRecoveryToken(
		m.ID,
		m.UserID,
		m.HashedToken,
		m.ExpiresAt,
		m.CreatedAt,
		m.UsedAt,
	)
}
