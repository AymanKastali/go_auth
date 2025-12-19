package handlers

import (
	"go_auth/src/application/dto"
	"go_auth/src/domain/ports/repositories"
	"go_auth/src/infra/mappers"
)

type ListUserOrganizationsHandler struct {
	orgRepo    repositories.OrganizationRepositoryPort
	uuidMapper mappers.UUIDMapper
}

func NewListUserOrganizationsHandler(
	orgRepo repositories.OrganizationRepositoryPort,
	uuidMapper mappers.UUIDMapper,
) *ListUserOrganizationsHandler {
	return &ListUserOrganizationsHandler{
		orgRepo:    orgRepo,
		uuidMapper: uuidMapper,
	}
}

func (h *ListUserOrganizationsHandler) Execute(ownerUserID string) ([]*dto.UserOrganizationResponse, error) {
	userIDVO, err := h.uuidMapper.FromString(ownerUserID)
	if err != nil {
		return nil, err
	}

	orgs, err := h.orgRepo.GetByOwner(userIDVO)
	if err != nil {
		return nil, err
	}

	responses := make([]*dto.UserOrganizationResponse, len(orgs))
	for i, org := range orgs {
		responses[i] = &dto.UserOrganizationResponse{
			ID:        org.ID.Value.String(),
			Name:      org.Name,
			Status:    string(org.Status),
			OwnerID:   org.OwnerUserID.Value.String(),
			CreatedAt: org.CreatedAt,
			UpdatedAt: org.UpdatedAt,
		}
	}

	return responses, nil
}
