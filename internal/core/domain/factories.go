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
	identity DeviceIdentity, // Already constructed and validated
	expiresAt Timepoint,
	now Timepoint,
) (*Session, error) {
	// The factory's job is now pure assembly.
	// NewSession will still perform business-rule validation
	// (e.g., ensuring expiresAt > now).
	return NewSession(
		id,
		token,
		identity,
		expiresAt,
		now,
	)
}
