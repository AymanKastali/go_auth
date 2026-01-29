package domain

import (
	"context"
)

type changePassword struct {
	userRepo    IUserRepository
	passwordSvc IPasswordService
	policy      IPasswordPolicy
	clock       IClock
}

func NewChangePassword(
	userRepo IUserRepository,
	passwordSvc IPasswordService,
	policy IPasswordPolicy,
	clock IClock,
) IChangePassword {
	return &changePassword{
		userRepo:    userRepo,
		passwordSvc: passwordSvc,
		policy:      policy,
		clock:       clock,
	}
}

func (s *changePassword) ChangePassword(
	ctx context.Context,
	user *User,
	oldPassword RawPassword,
	newPassword RawPassword,
) error {
	// 1. Verify Ownership/Knowledge of existing credential
	if !s.passwordSvc.Compare(oldPassword, user.HashedPassword()) {
		return ErrAuthenticationFailed
	}

	// 2. Enforce complexity/policy invariants
	if err := s.policy.Validate(newPassword); err != nil {
		return err
	}

	// 3. Transform Raw to Hashed
	newHash, err := s.passwordSvc.Hash(newPassword)
	if err != nil {
		return err
	}

	// 4. Update Aggregate state (this will also revoke sessions)
	return user.UpdatePassword(newHash, s.clock.Now())
}

// Password Reset Service
type passwordResetService struct {
	userRepo     IUserRepository
	recoveryRepo IRecoveryTokenRepository
	tokenSvc     ITokenService
	passwordSvc  IPasswordService
	pwPolicy     IPasswordPolicy
}

func NewPasswordResetService(
	ur IUserRepository,
	rr IRecoveryTokenRepository,
	ts ITokenService,
	ps IPasswordService,
	pp IPasswordPolicy,
) IPasswordResetService {
	return &passwordResetService{
		userRepo:     ur,
		recoveryRepo: rr,
		tokenSvc:     ts,
		passwordSvc:  ps,
		pwPolicy:     pp,
	}
}

func (s *passwordResetService) Reset(
	ctx context.Context,
	rawToken RawToken,
	newPassword RawPassword,
	now Timepoint,
) error {
	// 1. Hashing for DB Lookup
	hashedToken, err := s.tokenSvc.Hash(rawToken)
	if err != nil {
		return ErrInternal
	}

	// 2. Find and Validate the Recovery Token
	recovery, err := s.recoveryRepo.FindByHash(ctx, ReconstituteRecoveryTokenHash(hashedToken.String()))
	if err != nil {
		return err
	}
	if recovery == nil || !recovery.IsValid(now) {
		return ErrRecoveryTokenInvalid
	}

	// 3. Find the User
	user, err := s.userRepo.FindByID(ctx, recovery.UserID())
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// 4. Policy Check
	if err := s.pwPolicy.Validate(newPassword); err != nil {
		return err
	}

	// 5. Hash the Password
	newHashedPw, err := s.passwordSvc.Hash(newPassword)
	if err != nil {
		return ErrInternal
	}

	// 6. Update Aggregates (Domain State changes)
	if err := user.UpdatePassword(newHashedPw, now); err != nil {
		return err
	}
	if err := recovery.MarkAsUsed(now); err != nil {
		return err
	}

	// 7. Persist changes
	if err := s.userRepo.Save(ctx, user); err != nil {
		return err
	}
	return s.recoveryRepo.Save(ctx, recovery)
}

// --- Forgot Password Service ---
type forgotPasswordService struct {
	recoveryRepo   IRecoveryTokenRepository
	tokenSvc       ITokenService
	idGen          IIDGenerator
	recoveryPolicy IRecoveryPolicy // Added to match your Policy pattern
}

func NewForgotPasswordService(
	rr IRecoveryTokenRepository,
	ts ITokenService,
	idGen IIDGenerator,
	rp IRecoveryPolicy,
) IForgotPasswordService {
	return &forgotPasswordService{
		recoveryRepo:   rr,
		tokenSvc:       ts,
		idGen:          idGen,
		recoveryPolicy: rp,
	}
}

func (s *forgotPasswordService) Execute(
	ctx context.Context,
	user *User,
	now Timepoint,
) (RawToken, error) {
	// 1. Generate ID for the new Recovery Token Aggregate
	tid, err := s.idGen.GenerateRecoveryTokenID()
	if err != nil {
		return ZeroRawToken, err
	}

	// 2. Security Materials
	raw, err := s.tokenSvc.Generate()
	if err != nil {
		return ZeroRawToken, ErrInternal
	}

	hashed, err := s.tokenSvc.Hash(raw)
	if err != nil {
		return ZeroRawToken, ErrInternal
	}

	// 3. Clean up: Revoke any existing tokens for this user
	if err := s.recoveryRepo.RevokeAllForUser(ctx, user.ID(), now); err != nil {
		return ZeroRawToken, err
	}

	// 4. Build the RecoveryToken Aggregate
	// Use the Policy to determine expiry, similar to establishUserSessionService
	expiresAt := now.Add(s.recoveryPolicy.GetRecoveryTokenLifetime())

	token, err := NewRecoveryToken(
		tid,
		user.ID(),
		ReconstituteRecoveryTokenHash(hashed.String()),
		expiresAt,
		now,
	)
	if err != nil {
		return ZeroRawToken, err
	}

	// 5. Persist the record
	if err := s.recoveryRepo.Save(ctx, token); err != nil {
		return ZeroRawToken, err
	}

	return raw, nil
}
