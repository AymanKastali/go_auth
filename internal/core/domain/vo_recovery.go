package domain

var (
	ZeroRecoveryTokenRaw = RecoveryTokenRaw{}
	ZeroRecoveryTokenID  = RecoveryTokenID{}
)

// RecoveryTokenID is a unique identifier for the recovery record.
type RecoveryTokenID struct{ value string }

func NewRecoveryTokenID(v string) (RecoveryTokenID, error) {
	if v == "" {
		return RecoveryTokenID{}, ErrRecoveryTokenIDRequired
	}
	return RecoveryTokenID{value: v}, nil
}

func ReconstituteRecoveryTokenID(v string) RecoveryTokenID {
	return RecoveryTokenID{value: v}
}

func (vo RecoveryTokenID) String() string { return vo.value }

// RecoveryTokenHash represents the one-way hash of the token stored in the DB.
type RecoveryTokenHash struct{ value string }

func (vo RecoveryTokenHash) String() string { return vo.value }

func NewRecoveryTokenHash(v string) (RecoveryTokenHash, error) {
	if v == "" {
		return RecoveryTokenHash{}, ErrRecoveryTokenInvalid
	}
	return RecoveryTokenHash{value: v}, nil
}

func ReconstituteRecoveryTokenHash(v string) RecoveryTokenHash {
	return RecoveryTokenHash{value: v}
}

type RecoveryTokenRaw struct{ value string }

func NewRecoveryTokenRaw(v string) (RecoveryTokenRaw, error) {
	if v == "" {
		return ZeroRecoveryTokenRaw, ErrRecoveryTokenInvalid
	}
	return RecoveryTokenRaw{value: v}, nil
}

func (vo RecoveryTokenRaw) String() string { return vo.value }
