package domain

import (
	"regexp"
	"strings"
	"time"
)

type ILoginPolicy interface {
	GetMaxAttempts() int
	GetLockoutDuration() time.Duration
}

type IPasswordPolicy interface {
	Validate(rawPassword string) (ValidatedPassword, error)
}

type IRegisterPolicy interface {
	Validate(email Email) error
}

type ISessionPolicy interface {
	GetSessionLifetime() time.Duration
	GetMaxActiveSessions() int
}

type IRecoveryPolicy interface {
	GetRecoveryTokenLifetime() time.Duration
}

var (
	upperRegex   = regexp.MustCompile(`[A-Z]`)
	numberRegex  = regexp.MustCompile(`[0-9]`)
	specialRegex = regexp.MustCompile(`[!@#\$%\^&\*]`)
)

// RegisterPolicyConfig holds the configuration for registration rules.
type RegisterPolicyConfig struct {
	AllowPublic    bool
	BlockedDomains []string
}

type registerPolicy struct {
	allowPublicSignUp bool
	blockedDomains    []string
}

func NewRegisterPolicy(cfg RegisterPolicyConfig) IRegisterPolicy {
	return &registerPolicy{
		allowPublicSignUp: cfg.AllowPublic,
		blockedDomains:    cfg.BlockedDomains,
	}
}

func (p *registerPolicy) Validate(email Email) error {
	// 1. Check if the "Open for Business" sign is up
	if !p.allowPublicSignUp {
		return ErrRegistrationDisabled
	}

	// 2. Domain Blacklisting (e.g., prevent burner emails)
	emailStr := strings.ToLower(email.String())
	for _, domain := range p.blockedDomains {
		if strings.HasSuffix(emailStr, "@"+strings.ToLower(domain)) {
			return ErrEmailDomainBlocked
		}
	}

	return nil
}

// PasswordPolicyConfig holds the configuration for password validation rules.
type PasswordPolicyConfig struct {
	MinLength      uint8
	MaxLength      uint8
	RequireUpper   bool
	RequireNumber  bool
	RequireSpecial bool
}

type passwordPolicy struct {
	minLength      uint8
	maxLength      uint8
	requireUpper   bool
	requireNumber  bool
	requireSpecial bool
}

func NewPasswordPolicy(cfg PasswordPolicyConfig) IPasswordPolicy {
	return &passwordPolicy{
		minLength:      cfg.MinLength,
		maxLength:      cfg.MaxLength,
		requireUpper:   cfg.RequireUpper,
		requireNumber:  cfg.RequireNumber,
		requireSpecial: cfg.RequireSpecial,
	}
}

func (p *passwordPolicy) Validate(password string) (ValidatedPassword, error) {
	length := len(password)

	// 1. Length Checks
	if length < int(p.minLength) {
		return ZeroValidatedPassword, ErrPasswordTooShort
	}
	if length > int(p.maxLength) {
		return ZeroValidatedPassword, ErrPasswordTooLong
	}

	// 2. Complexity Checks
	if p.requireUpper && !upperRegex.MatchString(password) {
		return ZeroValidatedPassword, ErrPasswordNoUpper
	}
	if p.requireNumber && !numberRegex.MatchString(password) {
		return ZeroValidatedPassword, ErrPasswordNoNumber
	}
	if p.requireSpecial && !specialRegex.MatchString(password) {
		return ZeroValidatedPassword, ErrPasswordNoSpecial
	}

	return ValidatedPassword{value: password}, nil
}

// SessionPolicyConfig holds the configuration for session management rules.
type SessionPolicyConfig struct {
	Lifetime  time.Duration
	MaxActive uint8
}

type sessionPolicy struct {
	lifetime  time.Duration
	maxActive uint8
}

func NewSessionPolicy(cfg SessionPolicyConfig) ISessionPolicy {
	return &sessionPolicy{
		lifetime:  cfg.Lifetime,
		maxActive: cfg.MaxActive,
	}
}

func (p *sessionPolicy) GetSessionLifetime() time.Duration {
	return p.lifetime
}

func (p *sessionPolicy) GetMaxActiveSessions() int {
	return int(p.maxActive)
}

type IAccessPolicy interface {
	GetAccessLifetime() time.Duration
}

// AccessPolicyConfig holds the configuration for access token rules.
type AccessPolicyConfig struct {
	Lifetime time.Duration
}

type accessPolicy struct {
	lifetime time.Duration
}

func NewAccessPolicy(cfg AccessPolicyConfig) IAccessPolicy {
	return &accessPolicy{
		lifetime: cfg.Lifetime,
	}
}

func (p *accessPolicy) GetAccessLifetime() time.Duration {
	return p.lifetime
}

// RecoveryPolicyConfig holds the configuration for recovery token rules.
type RecoveryPolicyConfig struct {
	Lifetime time.Duration
}

type recoveryPolicy struct {
	lifetime time.Duration
}

func NewRecoveryPolicy(cfg RecoveryPolicyConfig) IRecoveryPolicy {
	lifetime := cfg.Lifetime
	if lifetime <= 0 {
		lifetime = 15 * time.Minute // Safe default
	}
	return &recoveryPolicy{lifetime: lifetime}
}

func (p *recoveryPolicy) GetRecoveryTokenLifetime() time.Duration {
	return p.lifetime
}

// IActivationPolicy defines the business rules for account activation.
type IActivationPolicy interface {
	RequiresEmailActivation() bool
	GetActivationTokenLifetime() time.Duration
}

// ActivationPolicyConfig holds the configuration for activation rules.
type ActivationPolicyConfig struct {
	RequireEmail  bool
	TokenLifetime time.Duration
}

type activationPolicy struct {
	requireEmail  bool
	tokenLifetime time.Duration
}

func NewActivationPolicy(cfg ActivationPolicyConfig) IActivationPolicy {
	lifetime := cfg.TokenLifetime
	if lifetime <= 0 {
		lifetime = 24 * time.Hour // Safe default
	}
	return &activationPolicy{
		requireEmail:  cfg.RequireEmail,
		tokenLifetime: lifetime,
	}
}

func (p *activationPolicy) RequiresEmailActivation() bool {
	return p.requireEmail
}

func (p *activationPolicy) GetActivationTokenLifetime() time.Duration {
	return p.tokenLifetime
}

// LoginPolicyConfig holds the configuration for login attempt limiting.
type LoginPolicyConfig struct {
	MaxAttempts     int
	LockoutDuration time.Duration
}

type loginPolicy struct {
	maxAttempts     int
	lockoutDuration time.Duration
}

func NewLoginPolicy(cfg LoginPolicyConfig) ILoginPolicy {
	maxAttempts := cfg.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	lockoutDuration := cfg.LockoutDuration
	if lockoutDuration <= 0 {
		lockoutDuration = 15 * time.Minute
	}
	return &loginPolicy{
		maxAttempts:     maxAttempts,
		lockoutDuration: lockoutDuration,
	}
}

func (p *loginPolicy) GetMaxAttempts() int              { return p.maxAttempts }
func (p *loginPolicy) GetLockoutDuration() time.Duration { return p.lockoutDuration }
