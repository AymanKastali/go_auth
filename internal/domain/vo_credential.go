package domain

var (
	ZeroHashedPassword     = HashedPassword{}
	ZeroValidatedPassword  = ValidatedPassword{}
)

// --- HashedPassword ---
type HashedPassword struct{ value string }

func NewHashedPassword(value string) (HashedPassword, error) {
	if value == "" {
		return ZeroHashedPassword, ErrUserPasswordRequired
	}
	return HashedPassword{value: value}, nil
}
func ReconstituteHashedPassword(value string) HashedPassword { return HashedPassword{value: value} }
func (vo HashedPassword) String() string                     { return vo.value }
func (vo HashedPassword) IsEmpty() bool                      { return vo.value == "" }

// --- ValidatedPassword ---
type ValidatedPassword struct{ value string }

func ReconstituteValidatedPassword(value string) ValidatedPassword { return ValidatedPassword{value: value} }
func (vo ValidatedPassword) String() string                        { return vo.value }
func (vo ValidatedPassword) IsEmpty() bool                         { return vo.value == "" }
