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
	InitiateActivation(
		user *User,
		now Timepoint,
	) (RawToken, *ActivationToken, error)
	ConfirmActivation(
		user *User,
		activation *ActivationToken,
		now Timepoint,
	) error
}

type userAccountManager struct {
	tokenSvc         ITokenService
	passwordMgr      IPasswordManager
	idGen            IIDGenerator
	recoveryPolicy   IRecoveryPolicy
	activationPolicy IActivationPolicy
}

func NewUserAccountManager(
	tokenSvc ITokenService,
	passwordMgr IPasswordManager,
	idGen IIDGenerator,
	recoveryPolicy IRecoveryPolicy,
	activationPolicy IActivationPolicy,
) IUserAccountManager {
	return &userAccountManager{
		tokenSvc:         tokenSvc,
		passwordMgr:      passwordMgr,
		idGen:            idGen,
		recoveryPolicy:   recoveryPolicy,
		activationPolicy: activationPolicy,
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

func (m *userAccountManager) InitiateActivation(
	user *User,
	now Timepoint,
) (RawToken, *ActivationToken, error) {
	// 1. Generate raw token
	rawToken, err := m.tokenSvc.Generate()
	if err != nil {
		return ZeroRawToken, nil, err
	}

	// 2. Hash for storage
	hashedToken, err := m.tokenSvc.HashActivationToken(rawToken)
	if err != nil {
		return ZeroRawToken, nil, err
	}

	// 3. Policy application
	expirationTime := now.Add(m.activationPolicy.GetActivationTokenLifetime())

	// 4. Generate ID
	id, err := m.idGen.GenerateActivationTokenID()
	if err != nil {
		return ZeroRawToken, nil, err
	}

	// 5. Aggregate construction
	activationToken, err := NewActivationToken(
		id,
		user.ID(),
		hashedToken,
		expirationTime,
		now,
	)
	if err != nil {
		return ZeroRawToken, nil, err
	}

	return rawToken, activationToken, nil
}

func (m *userAccountManager) ConfirmActivation(
	user *User,
	activation *ActivationToken,
	now Timepoint,
) error {
	// 1. Validate activation token
	if activation.IsExpired(now) {
		return ErrActivationTokenExpired
	}
	if activation.IsUsed() {
		return ErrActivationTokenAlreadyUsed
	}
	if !activation.IsValid(now) {
		return ErrActivationTokenInvalid
	}

	// 2. Cross-Aggregate Invariant: Token Ownership
	if !activation.UserID().Equal(user.ID()) {
		return ErrActivationTokenInvalid
	}

	// 3. Check if user is already active
	if user.IsActive() {
		return ErrUserAlreadyActive
	}

	// 4. Execute State Transitions
	if err := user.Activate(now); err != nil {
		return err
	}
	return activation.MarkAsUsed(now)
}
