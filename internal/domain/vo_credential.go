package domain

var (
	ZeroHashedPassword = HashedPassword{}
	ZeroRawPassword    = RawPassword{}
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

// --- RawPassword ---
type RawPassword struct{ value string }

func NewRawPassword(value string) (RawPassword, error) {
	if value == "" {
		return ZeroRawPassword, ErrUserPasswordRequired
	}
	return RawPassword{value: value}, nil
}
func (vo RawPassword) String() string { return vo.value }
func (vo RawPassword) IsEmpty() bool  { return vo.value == "" }
