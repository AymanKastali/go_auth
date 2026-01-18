package dto

type ManageRoleRequest struct {
	UserID string `json:"user_id" validate:"required"`
	Role   string `json:"role" validate:"required"`
	Action string `json:"action" validate:"required,oneof=grant revoke"`
}
