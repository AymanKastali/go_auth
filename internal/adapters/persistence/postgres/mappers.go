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
	uid, err := domain.NewUserID(m.ID)
	if err != nil {
		return nil, domain.NewInternalError("failed to reconstitute user id from database", err)
	}

	email, err := domain.NewEmail(m.Email)
	if err != nil {
		return nil, domain.NewInternalError("failed to reconstitute email from database", err)
	}

	passwordHash, err := domain.NewHashedPassword(m.PasswordHash)
	if err != nil {
		return nil, domain.NewInternalError("failed to reconstitute password hash from database", err)
	}

	roles := make([]domain.Role, len(m.Roles))
	for i, rName := range m.Roles {
		role, err := domain.NewRole(rName)
		if err != nil {
			return nil, domain.NewInternalError("failed to reconstitute role from database", err)
		}
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
	if s.RevokedAt() != nil {
		t := s.RevokedAt().Time()
		revokedAt = &t
	}

	return SessionModel{
		ID:           s.ID().String(),
		UserID:       userID,
		HashedToken:  s.HashedToken().String(),
		Fingerprint:  s.Fingerprint().String(),
		UserAgent:    s.UserAgent(),
		IPAddress:    s.IPAddress(),
		ExpiresAt:    s.ExpiresAt().Time(),
		LastActiveAt: s.LastActiveAt().Time(),
		RevokedAt:    revokedAt,
	}
}

func toSessionDomain(m SessionModel) (domain.Session, error) {
	sid, err := domain.NewSessionID(m.ID)
	if err != nil {
		return domain.ZeroSession, domain.NewInternalError("failed to reconstitute session id from database", err)
	}

	token, err := domain.NewHashedToken(m.HashedToken)
	if err != nil {
		return domain.ZeroSession, domain.NewInternalError("failed to reconstitute hashed token from database", err)
	}

	fingerprint, err := domain.NewDeviceFingerprint(m.Fingerprint)
	if err != nil {
		return domain.ZeroSession, domain.NewInternalError("failed to reconstitute fingerprint from database", err)
	}

	var revokedAt *domain.Timepoint
	if m.RevokedAt != nil {
		t := domain.ReconstituteTimepoint(*m.RevokedAt)
		revokedAt = &t
	}

	session := domain.ReconstituteSession(
		sid,
		token,
		fingerprint,
		m.UserAgent,
		m.IPAddress,
		domain.ReconstituteTimepoint(m.ExpiresAt),
		domain.ReconstituteTimepoint(m.LastActiveAt),
		revokedAt,
	)

	return session, nil
}
