package handlers

import (
	"errors"
	"go_auth/src/application/dto"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
	value_objects "go_auth/src/domain/value_objects"
	"go_auth/src/infra/mappers"
)

type RegisterOrganizationHandler struct {
	userRepo            repositories.UserRepositoryPort
	orgRepo             repositories.OrganizationRepositoryPort
	membershipRepo      repositories.MembershipRepositoryPort
	idFactory           factories.IDFactory
	organizationFactory factories.OrganizationFactory
	membershipFactory   factories.MembershipFactory
	uuidMapper          mappers.UUIDMapper
}

func NewRegisterOrganizationHandler(
	userRepo repositories.UserRepositoryPort,
	orgRepo repositories.OrganizationRepositoryPort,
	membershipRepo repositories.MembershipRepositoryPort,
	idFactory factories.IDFactory,
	organizationFactory factories.OrganizationFactory,
	membershipFactory factories.MembershipFactory,
	uuidMapper mappers.UUIDMapper,
) *RegisterOrganizationHandler {
	return &RegisterOrganizationHandler{
		userRepo:            userRepo,
		orgRepo:             orgRepo,
		membershipRepo:      membershipRepo,
		idFactory:           idFactory,
		organizationFactory: organizationFactory,
		membershipFactory:   membershipFactory,
		uuidMapper:          uuidMapper,
	}
}

func (h *RegisterOrganizationHandler) Execute(
	ownerUserID string,
	name string,
) (*dto.CreatedOrganizationResponse, error) {
	userIDVO, err := h.uuidMapper.FromString(ownerUserID)
	if err != nil {
		return nil, err
	}

	owner, err := h.userRepo.GetByID(userIDVO)
	if err != nil {
		return nil, err
	}
	if owner == nil {
		return nil, errors.New("owner user does not exist")
	}

	// 1. Create Organization
	orgID := h.idFactory.NewOrganizationID()

	org, err := h.organizationFactory.New(
		orgID,
		name,
		userIDVO,
		value_objects.OrgActive,
	)
	if err != nil {
		return nil, err
	}

	// 2. Persist Organization
	if err := h.orgRepo.Save(org); err != nil {
		return nil, err
	}

	// 3. Create OWNER membership
	membershipID := h.idFactory.NewMembershipID()

	membership, err := h.membershipFactory.New(
		membershipID,
		userIDVO,
		org.ID,
		value_objects.RoleOwner,
		value_objects.MembershipActive,
	)
	if err != nil {
		return nil, err
	}

	// 4. Persist Membership
	if err := h.membershipRepo.Save(membership); err != nil {
		return nil, err
	}

	// 5. Return DTO
	return &dto.CreatedOrganizationResponse{
		ID:        org.ID.Value.String(),
		Name:      org.Name,
		Status:    string(org.Status),
		OwnerID:   org.OwnerUserID.Value.String(),
		CreatedAt: org.CreatedAt,
	}, nil
}
