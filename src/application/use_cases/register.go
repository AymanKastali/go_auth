package usecases

import (
	"context"
	"go_auth/src/application/dto"
	"go_auth/src/domain/entities"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/events"
	valueobjects "go_auth/src/domain/value_objects"

	domainrepo "go_auth/src/domain/ports/repositories"
	domainservice "go_auth/src/domain/ports/services"
)

type RegisterHandler struct {
	UserRepo    domainrepo.UserRepository
	PasswordSvc domainservice.PasswordService
	// optionally an event publisher, omitted for brevity
}

func NewRegisterHandler(u domainrepo.UserRepository, p domainservice.PasswordService) *RegisterHandler {
	return &RegisterHandler{UserRepo: u, PasswordSvc: p}
}

func (h *RegisterHandler) Handle(ctx context.Context, req dto.RegisterRequest) (*dto.AuthResponse, error) {
	// validate email
	emailVO, err := valueobjects.NewEmail(req.Email)
	if err != nil {
		return nil, err
	}

	// check existence
	existing, _ := h.UserRepo.GetByEmail(emailVO)
	if existing != nil {
		return nil, errors.ErrEmailAlreadyRegistered
	}

	// hash password
	hash, err := h.PasswordSvc.Hash(req.Password)
	if err != nil {
		return nil, err
	}
	pw := valueobjects.NewPasswordHash(hash)
	uid := valueobjects.NewUserID()
	user := entities.NewUser(uid, emailVO, pw)

	if err := h.UserRepo.Save(user); err != nil {
		return nil, err
	}

	// publish event (omitted: just demonstrate)
	_ = events.UserRegistered{UserID: uid}

	// Return nothing (or auto-login if you prefer). We'll return nil for now.
	return nil, nil
}
