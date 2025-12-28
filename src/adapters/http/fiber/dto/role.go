package dto

type ManageRoleRequest struct {
	UserId string `json:"user_id" binding:"required"`
	Role   string `json:"role" binding:"required"`
	Action string `json:"action" binding:"required,oneof=grant revoke"`
}
