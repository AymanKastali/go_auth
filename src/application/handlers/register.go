package handlers

import (
	"go_auth/src/application/dto"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/events"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
	valueobjects "go_auth/src/domain/value_objects"

	"go_auth/src/application/ports/services"
)

type RegisterHandler struct {
	userRepository repositories.UserRepositoryPort
	passwordHasher services.HashPasswordPort
	idFactory      factories.IDFactory
	emailFactory   factories.EmailFactory
	pwdHashFactory factories.PasswordHashFactory
	userFactory    factories.UserFactory
}

func NewRegisterHandler(
	userRepository repositories.UserRepositoryPort,
	passwordHasher services.HashPasswordPort,
	idFactory factories.IDFactory,
	emailFactory factories.EmailFactory,
	pwHashFactory factories.PasswordHashFactory,
	userFactory factories.UserFactory,
) *RegisterHandler {
	return &RegisterHandler{
		userRepository: userRepository,
		passwordHasher: passwordHasher,
		idFactory:      idFactory,
		emailFactory:   emailFactory,
		pwdHashFactory: pwHashFactory,
		userFactory:    userFactory,
	}
}

func (h *RegisterHandler) Execute(email string, password string) (*dto.AuthResponse, error) {

	// Use the injected factory
	emailVO, err := h.emailFactory.New(email)
	if err != nil {
		return nil, err
	}

	// check existence
	existing, _ := h.userRepository.GetByEmail(emailVO)
	if existing != nil {
		return nil, errors.ErrEmailAlreadyRegistered
	}

	// hash password
	hash, err := h.passwordHasher.Hash(password)
	if err != nil {
		return nil, err
	}

	// Use the injected factory
	pw := h.pwdHashFactory.New(hash)

	// Use the injected factory
	user, err := h.userFactory.New(
		h.idFactory.NewUserID(),
		emailVO,
		pw,
		valueobjects.UserActive,
	)

	if err != nil {
		return nil, err
	}

	if err := h.userRepository.Save(user); err != nil {
		return nil, err
	}

	// publish event (omitted: just demonstrate)
	_ = events.UserRegistered{UserID: user.ID}

	return nil, nil
}
