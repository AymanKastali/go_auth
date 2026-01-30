package domain

import "regexp"

var (
	ZeroUserID = UserID{}
	ZeroEmail  = Email{}
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// --- UserID ---
type UserID struct{ value string }

func NewUserID(value string) (UserID, error) {
	if value == "" {
		return ZeroUserID, ErrUserIDRequired
	}
	return UserID{value: value}, nil
}
func ReconstituteUserID(value string) UserID { return UserID{value: value} }
func (vo UserID) String() string             { return vo.value }
func (vo UserID) IsEmpty() bool              { return vo.value == "" }
func (vo UserID) Equal(other UserID) bool    { return vo.value == other.value }

// --- Email ---
type Email struct{ value string }

func NewEmail(value string) (Email, error) {
	if value == "" {
		return ZeroEmail, ErrUserEmailRequired
	}
	if !emailRegex.MatchString(value) {
		return ZeroEmail, ErrUserEmailInvalid
	}
	return Email{value: value}, nil
}
func ReconstituteEmail(email string) Email { return Email{value: email} }
func (vo Email) String() string            { return vo.value }
func (vo Email) IsEmpty() bool             { return vo.value == "" }
func (vo Email) Equal(other Email) bool    { return vo.value == other.value }
