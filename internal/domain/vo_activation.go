package domain

var (
	ZeroActivationTokenID   = ActivationTokenID{}
	ZeroActivationTokenHash = ActivationTokenHash{}
)

// ActivationTokenID is a unique identifier for the activation record.
type ActivationTokenID struct{ value string }

func NewActivationTokenID(v string) (ActivationTokenID, error) {
	if v == "" {
		return ActivationTokenID{}, ErrActivationTokenIDRequired
	}
	return ActivationTokenID{value: v}, nil
}

func ReconstituteActivationTokenID(v string) ActivationTokenID {
	return ActivationTokenID{value: v}
}

func (vo ActivationTokenID) String() string { return vo.value }

// ActivationTokenHash represents the one-way hash of the token stored in the DB.
type ActivationTokenHash struct{ value string }

func (vo ActivationTokenHash) String() string { return vo.value }

func NewActivationTokenHash(v string) (ActivationTokenHash, error) {
	if v == "" {
		return ActivationTokenHash{}, ErrActivationTokenInvalid
	}
	return ActivationTokenHash{value: v}, nil
}

func ReconstituteActivationTokenHash(v string) ActivationTokenHash {
	return ActivationTokenHash{value: v}
}
