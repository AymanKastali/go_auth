package domain

type IPasswordManager interface {
	ValidateAndHashNewPassword(raw RawPassword) (HashedPassword, error)
	Compare(raw RawPassword, hashed HashedPassword) bool
}

type passwordManager struct {
	svc    IPasswordService
	policy IPasswordPolicy
}

func NewPasswordManager(
	svc IPasswordService,
	policy IPasswordPolicy,
) *passwordManager {
	return &passwordManager{
		svc:    svc,
		policy: policy,
	}
}

func (m *passwordManager) ValidateAndHashNewPassword(raw RawPassword) (HashedPassword, error) {
	if err := m.policy.Validate(raw); err != nil {
		return ZeroHashedPassword, err
	}
	return m.svc.Hash(raw)
}

func (m *passwordManager) Compare(raw RawPassword, hashed HashedPassword) bool {
	return m.svc.Compare(raw, hashed)
}
