package domain

type IUserAccountManager interface {
	InitiatePasswordReset(
		user *User,
		now Timepoint,
	) (RawToken, *RecoveryToken, error)
	ChangePassword(
		user *User,
		oldPass RawPassword,
		newPass RawPassword,
		now Timepoint,
	) error
	ResetPasswordByToken(
		user *User,
		recovery *RecoveryToken,
		newPassword RawPassword,
		now Timepoint,
	) error
}

type userAccountManager struct {
	tokenSvc       ITokenService
	passwordMgr    IPasswordManager
	idGen          IIDGenerator
	recoveryPolicy IRecoveryPolicy
}

func NewUserAccountManager(
	tokenSvc ITokenService,
	passwordMgr IPasswordManager,
	idGen IIDGenerator,
	recoveryPolicy IRecoveryPolicy,
) IUserAccountManager {
	return &userAccountManager{
		tokenSvc:       tokenSvc,
		passwordMgr:    passwordMgr,
		idGen:          idGen,
		recoveryPolicy: recoveryPolicy,
	}
}

func (manager *userAccountManager) InitiatePasswordReset(
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
	user *User,
	recovery *RecoveryToken,
	newPassword RawPassword,
	now Timepoint,
) error {
	// 1. Validate Recovery Token
	if !recovery.IsValid(now) {
		return ErrRecoveryTokenInvalid
	}

	// 2. Cross-Aggregate Invariant: Token Ownership
	if !recovery.UserID().Equal(user.ID()) {
		return ErrInvalidRecoveryAttempt
	}

	// 3. Validate and hash the new password
	newHash, err := m.passwordMgr.ValidateAndHashNewPassword(newPassword)
	if err != nil {
		return err
	}

	// 4. Execute State Transitions
	if err := user.UpdatePassword(newHash, now); err != nil {
		return err
	}
	return recovery.MarkAsUsed(now)
}
