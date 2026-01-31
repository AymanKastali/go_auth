package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------
// Register Policy
// ---------------------------------------------------------------

func TestRegisterPolicy_Validate(t *testing.T) {
	email := ReconstituteEmail("user@example.com")
	blockedEmail := ReconstituteEmail("user@throwaway.com")

	t.Run("public_allowed", func(t *testing.T) {
		p := NewRegisterPolicy(RegisterPolicyConfig{AllowPublic: true})
		assert.NoError(t, p.Validate(email))
	})

	t.Run("disabled", func(t *testing.T) {
		p := NewRegisterPolicy(RegisterPolicyConfig{AllowPublic: false})
		assert.ErrorIs(t, p.Validate(email), ErrRegistrationDisabled)
	})

	t.Run("blocked_domain", func(t *testing.T) {
		p := NewRegisterPolicy(RegisterPolicyConfig{
			AllowPublic:    true,
			BlockedDomains: []string{"throwaway.com"},
		})
		assert.ErrorIs(t, p.Validate(blockedEmail), ErrEmailDomainBlocked)
	})

	t.Run("case_insensitive_domain", func(t *testing.T) {
		upper := ReconstituteEmail("USER@THROWAWAY.COM")
		p := NewRegisterPolicy(RegisterPolicyConfig{
			AllowPublic:    true,
			BlockedDomains: []string{"throwaway.com"},
		})
		assert.ErrorIs(t, p.Validate(upper), ErrEmailDomainBlocked)
	})

	t.Run("allowed_domain_passes", func(t *testing.T) {
		p := NewRegisterPolicy(RegisterPolicyConfig{
			AllowPublic:    true,
			BlockedDomains: []string{"throwaway.com"},
		})
		assert.NoError(t, p.Validate(email))
	})
}

// ---------------------------------------------------------------
// Password Policy
// ---------------------------------------------------------------

func TestPasswordPolicy_Validate(t *testing.T) {
	fullPolicy := NewPasswordPolicy(PasswordPolicyConfig{
		MinLength:      8,
		MaxLength:      64,
		RequireUpper:   true,
		RequireNumber:  true,
		RequireSpecial: true,
	})

	validPwd, _ := NewRawPassword("Str0ng!Pass")

	t.Run("meets_all", func(t *testing.T) {
		require.NoError(t, fullPolicy.Validate(validPwd))
	})

	t.Run("too_short", func(t *testing.T) {
		p, _ := NewRawPassword("Sh1!")
		assert.ErrorIs(t, fullPolicy.Validate(p), ErrPasswordTooShort)
	})

	t.Run("too_long", func(t *testing.T) {
		long, _ := NewRawPassword(string(make([]byte, 65)))
		assert.ErrorIs(t, fullPolicy.Validate(long), ErrPasswordTooLong)
	})

	t.Run("no_upper", func(t *testing.T) {
		p, _ := NewRawPassword("str0ng!pass")
		assert.ErrorIs(t, fullPolicy.Validate(p), ErrPasswordNoUpper)
	})

	t.Run("no_number", func(t *testing.T) {
		p, _ := NewRawPassword("Strong!Pass")
		assert.ErrorIs(t, fullPolicy.Validate(p), ErrPasswordNoNumber)
	})

	t.Run("no_special", func(t *testing.T) {
		p, _ := NewRawPassword("Str0ngPasss")
		assert.ErrorIs(t, fullPolicy.Validate(p), ErrPasswordNoSpecial)
	})

	t.Run("all_disabled", func(t *testing.T) {
		lax := NewPasswordPolicy(PasswordPolicyConfig{MinLength: 1, MaxLength: 255})
		p, _ := NewRawPassword("a")
		assert.NoError(t, lax.Validate(p))
	})
}

// ---------------------------------------------------------------
// Session Policy
// ---------------------------------------------------------------

func TestSessionPolicy(t *testing.T) {
	p := NewSessionPolicy(SessionPolicyConfig{
		Lifetime:  24 * time.Hour,
		MaxActive: 5,
	})
	assert.Equal(t, 24*time.Hour, p.GetSessionLifetime())
	assert.Equal(t, 5, p.GetMaxActiveSessions())
}

// ---------------------------------------------------------------
// Access Policy
// ---------------------------------------------------------------

func TestAccessPolicy(t *testing.T) {
	p := NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute})
	assert.Equal(t, 15*time.Minute, p.GetAccessLifetime())
}

// ---------------------------------------------------------------
// Recovery Policy
// ---------------------------------------------------------------

func TestRecoveryPolicy(t *testing.T) {
	t.Run("configured_lifetime", func(t *testing.T) {
		p := NewRecoveryPolicy(RecoveryPolicyConfig{Lifetime: 30 * time.Minute})
		assert.Equal(t, 30*time.Minute, p.GetRecoveryTokenLifetime())
	})

	t.Run("zero_defaults_to_15m", func(t *testing.T) {
		p := NewRecoveryPolicy(RecoveryPolicyConfig{})
		assert.Equal(t, 15*time.Minute, p.GetRecoveryTokenLifetime())
	})
}
