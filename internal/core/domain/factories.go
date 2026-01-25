package domain

// UserFactory implementation
type userFactory struct{}

func NewUserFactory() IUserFactory {
	return &userFactory{}
}

func (f *userFactory) Build(id UserID, email Email, password HashedPassword, now Timepoint) (*User, error) {
	// We use the New constructor to ensure all business invariants
	// defined at the "Birth" of a User are respected.
	return NewUser(
		id,
		email,
		password,
		now,
	)
}

// SessionFactory implementation
type sessionFactory struct{}

func NewSessionFactory() ISessionFactory {
	return &sessionFactory{}
}

func (f *sessionFactory) Build(
	id SessionID,
	token HashedToken,
	fp DeviceFingerprint,
	ua string,
	ip string,
	expiresAt Timepoint,
	now Timepoint,
) (*Session, error) {
	// We call NewSession which validates that the expiration
	// isn't in the past relative to 'now'.
	return NewSession(
		id,
		token,
		fp,
		ua,
		ip,
		expiresAt,
		now,
	)
}
