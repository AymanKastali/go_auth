package domain

import (
	"context"
)

type IUserAccountManager interface {
	InitiatePasswordReset(
		ctx context.Context,
		user *User,
		now Timepoint,
	) (RawToken, *RecoveryToken, error)
	ChangePassword(
		ctx context.Context,
		user *User,
		oldPass RawPassword,
		newPass RawPassword,
		now Timepoint,
	) error
	ResetPasswordByToken(
		ctx context.Context,
		token RawToken,
		newPassword RawPassword,
		now Timepoint,
	) error
}

type userAccountManager struct {
	userRepo       IUserRepository
	recoveryRepo   IRecoveryTokenRepository
	tokenSvc       ITokenService
	passwordMgr    IPasswordManager
	idGen          IIDGenerator
	recoveryPolicy IRecoveryPolicy
}

func NewUserAccountManager(
	userRepo IUserRepository,
	recoveryRepo IRecoveryTokenRepository,
	tokenSvc ITokenService,
	passwordMgr IPasswordManager,
	idGen IIDGenerator,
	recoveryPolicy IRecoveryPolicy,
) IUserAccountManager {
	return &userAccountManager{
		userRepo:       userRepo,
		recoveryRepo:   recoveryRepo,
		tokenSvc:       tokenSvc,
		passwordMgr:    passwordMgr,
		idGen:          idGen,
		recoveryPolicy: recoveryPolicy,
	}
}

func (manager *userAccountManager) InitiatePasswordReset(
	ctx context.Context,
	user *User,
	now Timepoint,
) (RawToken, *RecoveryToken, error) {
	// 1. Invariant Checks
	if !user.IsActive() {
		return ZeroRawToken, nil, ErrUserInactive
	}

	// 2. Technical Logic
	rawToken, err := manager.tokenSvc.Generate()
	if err != nil {
		return ZeroRawToken, nil, err
	}

	hashedToken, err := manager.tokenSvc.HashRecoveryToken(rawToken)
	if err != nil {
		return ZeroRawToken, nil, err
	}

	// 3. Policy Application
	expirationTime := now.Add(manager.recoveryPolicy.GetRecoveryTokenLifetime())

	// 4. Aggregate Construction (The Service acts as a Factory coordinator)
	// We get the ID from the repository (identity generation is a repo responsibility)
	id, err := manager.idGen.GenerateRecoveryTokenID()
	if err != nil {
		return ZeroRawToken, nil, err
	}

	recoveryToken, err := NewRecoveryToken(
		id,
		user.ID(),
		hashedToken,
		expirationTime,
		now,
	)
	if err != nil {
		return ZeroRawToken, nil, err
	}

	return rawToken, recoveryToken, nil
}

func (m *userAccountManager) ChangePassword(
	ctx context.Context,
	user *User,
	oldPass RawPassword,
	newPass RawPassword,
	now Timepoint,
) error {
	if !m.passwordMgr.Compare(oldPass, user.HashedPassword()) {
		return ErrAuthenticationFailed
	}

	newHash, err := m.passwordMgr.ValidateAndHashNewPassword(newPass)
	if err != nil {
		return err
	}

	return user.UpdatePassword(newHash, now)
}

func (m *userAccountManager) ResetPasswordByToken(
	ctx context.Context,
	token RawToken,
	newPassword RawPassword,
	now Timepoint,
) error {
	// 1. Resolve Token Hash
	hashed, err := m.tokenSvc.HashRecoveryToken(token)
	if err != nil {
		return err
	}

	// 2. Fetch & Validate Recovery Aggregate
	recovery, err := m.recoveryRepo.FindByHash(ctx, hashed)
	if err != nil {
		return err
	}
	if recovery == nil || !recovery.IsValid(now) {
		return ErrRecoveryTokenInvalid
	}

	// 3. Fetch User Aggregate
	user, err := m.userRepo.FindByID(ctx, recovery.UserID())
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// 4. Cross-Aggregate Invariant: Token Ownership
	if !recovery.UserID().Equal(user.ID()) {
		return ErrInvalidRecoveryAttempt
	}

	// 5. Technical Process: Validation & Hashing combined
	// We delegate the "How" of the new secret to the Manager
	newHash, err := m.passwordMgr.ValidateAndHashNewPassword(newPassword)
	if err != nil {
		return err
	}

	// 6. Execute State Transitions
	if err := user.UpdatePassword(newHash, now); err != nil {
		return err
	}
	if err := recovery.MarkAsUsed(now); err != nil {
		return err
	}

	// 7. Atomic Persistence
	if err := m.userRepo.Save(ctx, user); err != nil {
		return err
	}
	return m.recoveryRepo.Save(ctx, recovery)
}
