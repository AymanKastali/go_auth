package usecases

import (
	"errors"
	"go_auth/src/application/dto"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
	valueobjects "go_auth/src/domain/value_objects"
)

type RegisterOrganizationUseCase struct {
	userRepo       repositories.UserRepositoryPort
	orgRepo        repositories.OrganizationRepositoryPort
	membershipRepo repositories.MembershipRepositoryPort

	idFactory           factories.IDFactory
	organizationFactory factories.OrganizationFactory
	membershipFactory   factories.MembershipFactory
}

func NewRegisterOrganizationUseCase(
	userRepo repositories.UserRepositoryPort,
	orgRepo repositories.OrganizationRepositoryPort,
	membershipRepo repositories.MembershipRepositoryPort,
	idFactory factories.IDFactory,
	organizationFactory factories.OrganizationFactory,
	membershipFactory factories.MembershipFactory,
) *RegisterOrganizationUseCase {
	return &RegisterOrganizationUseCase{
		userRepo:            userRepo,
		orgRepo:             orgRepo,
		membershipRepo:      membershipRepo,
		idFactory:           idFactory,
		organizationFactory: organizationFactory,
		membershipFactory:   membershipFactory,
	}
}

func (uc *RegisterOrganizationUseCase) Execute(
	ownerUserID valueobjects.UserID,
	name string,
) (*dto.CreatedOrganizationResponse, error) {

	owner, err := uc.userRepo.GetByID(ownerUserID)
	if err != nil {
		return nil, err
	}
	if owner == nil {
		return nil, errors.New("owner user does not exist")
	}

	// 1. Create Organization
	orgID := uc.idFactory.NewOrganizationID()

	org, err := uc.organizationFactory.New(
		orgID,
		name,
		ownerUserID,
		valueobjects.OrgActive,
	)
	if err != nil {
		return nil, err
	}

	// 2. Persist Organization
	if err := uc.orgRepo.Save(org); err != nil {
		return nil, err
	}

	// 3. Create OWNER membership
	membershipID := uc.idFactory.NewMembershipID()

	membership, err := uc.membershipFactory.New(
		membershipID,
		ownerUserID,
		org.ID,
		valueobjects.RoleOwner,
		valueobjects.MembershipActive,
	)
	if err != nil {
		return nil, err
	}

	// 4. Persist Membership
	if err := uc.membershipRepo.Save(membership); err != nil {
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
