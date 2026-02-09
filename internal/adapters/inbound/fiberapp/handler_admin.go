package fiberapp

import (
	"go_auth/internal/application"
	"log/slog"
	"strconv"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
)

type AdminHandler struct {
	validate         *validator.Validate
	listRoles        application.IListRolesUseCase
	getRole          application.IGetRoleUseCase
	createRole       application.ICreateRoleUseCase
	assignPermission application.IAssignPermissionUseCase
	revokePermission application.IRevokePermissionUseCase
	listUsers        application.IListUsersUseCase
	getUser          application.IGetUserByIDUseCase
	assignUserRole   application.IAssignUserRoleUseCase
	revokeUserRole   application.IRevokeUserRoleUseCase
	activateUser     application.IAdminActivateUserUseCase
	deactivateUser   application.IAdminDeactivateUserUseCase
	deleteUser       application.IAdminDeleteUserUseCase
	seedRoles        application.ISeedRolesUseCase
	validateAccess   application.IValidateAccessUseCase
}

func NewAdminHandler(
	validate *validator.Validate,
	listRoles application.IListRolesUseCase,
	getRole application.IGetRoleUseCase,
	createRole application.ICreateRoleUseCase,
	assignPermission application.IAssignPermissionUseCase,
	revokePermission application.IRevokePermissionUseCase,
	listUsers application.IListUsersUseCase,
	getUser application.IGetUserByIDUseCase,
	assignUserRole application.IAssignUserRoleUseCase,
	revokeUserRole application.IRevokeUserRoleUseCase,
	activateUser application.IAdminActivateUserUseCase,
	deactivateUser application.IAdminDeactivateUserUseCase,
	deleteUser application.IAdminDeleteUserUseCase,
	seedRoles application.ISeedRolesUseCase,
	validateAccess application.IValidateAccessUseCase,
) *AdminHandler {
	return &AdminHandler{
		validate:         validate,
		listRoles:        listRoles,
		getRole:          getRole,
		createRole:       createRole,
		assignPermission: assignPermission,
		revokePermission: revokePermission,
		listUsers:        listUsers,
		getUser:          getUser,
		assignUserRole:   assignUserRole,
		revokeUserRole:   revokeUserRole,
		activateUser:     activateUser,
		deactivateUser:   deactivateUser,
		deleteUser:       deleteUser,
		seedRoles:        seedRoles,
		validateAccess:   validateAccess,
	}
}

// --- Role Endpoints ---

// @Summary List all roles
// @Description Returns all roles with their permissions
// @Tags Admin - Roles
// @Security ApiKeyAuth
// @Produce json
// @Success 200 {object} SuccessResponse{data=[]RoleHTTPResponse}
// @Failure 403 {object} ErrorResponse
// @Router /api/v1/admin/roles [get]
func (h *AdminHandler) ListRoles(c fiber.Ctx) error {
	roles, err := h.listRoles.Execute(c.Context())
	if err != nil {
		return err
	}

	resp := make([]RoleHTTPResponse, len(roles))
	for i, r := range roles {
		resp[i] = toRoleHTTPResponse(r)
	}

	return SendOK(c, "roles listed", resp)
}

// @Summary Get role by ID
// @Description Returns a single role with its permissions
// @Tags Admin - Roles
// @Security ApiKeyAuth
// @Produce json
// @Param id path string true "Role ID"
// @Success 200 {object} SuccessResponse{data=RoleHTTPResponse}
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/roles/{id} [get]
func (h *AdminHandler) GetRole(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "role ID is required", nil)
	}

	role, err := h.getRole.Execute(c.Context(), id)
	if err != nil {
		return err
	}

	return SendOK(c, "role found", toRoleHTTPResponse(role))
}

// @Summary Create a new role
// @Description Creates a role with optional permissions
// @Tags Admin - Roles
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param request body CreateRoleRequest true "Role Details"
// @Success 201 {object} SuccessResponse{data=RoleHTTPResponse}
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Router /api/v1/admin/roles [post]
func (h *AdminHandler) CreateRole(c fiber.Ctx) error {
	logger := application.GetLogger(c.Context())

	var req CreateRoleRequest
	if err := c.Bind().Body(&req); err != nil {
		logger.Warn("create_role_binding_failed", slog.Any("error", err))
		return SendBadRequest(c, err.Error(), nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	cmd := application.CreateRoleCommand{
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}

	role, err := h.createRole.Execute(c.Context(), cmd)
	if err != nil {
		return err
	}

	return SendCreated(c, "role created", toRoleHTTPResponse(role))
}

// @Summary Assign permission to role
// @Description Adds a permission to an existing role
// @Tags Admin - Roles
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Param request body AssignPermissionRequest true "Permission"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/roles/{id}/permissions [post]
func (h *AdminHandler) AssignPermission(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "role ID is required", nil)
	}

	var req AssignPermissionRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	cmd := application.AssignPermissionCommand{
		RoleID:     id,
		Permission: req.Permission,
	}

	if err := h.assignPermission.Execute(c.Context(), cmd); err != nil {
		return err
	}

	return SendOK(c, "permission assigned", nil)
}

// @Summary Revoke permission from role
// @Description Removes a permission from an existing role
// @Tags Admin - Roles
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Param request body RevokePermissionRequest true "Permission"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/roles/{id}/permissions [delete]
func (h *AdminHandler) RevokePermission(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "role ID is required", nil)
	}

	var req RevokePermissionRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	cmd := application.RevokePermissionCommand{
		RoleID:     id,
		Permission: req.Permission,
	}

	if err := h.revokePermission.Execute(c.Context(), cmd); err != nil {
		return err
	}

	return SendOK(c, "permission revoked", nil)
}

// --- User Endpoints ---

// @Summary List users (paginated)
// @Description Returns a paginated list of users
// @Tags Admin - Users
// @Security ApiKeyAuth
// @Produce json
// @Param offset query int false "Offset" default(0)
// @Param limit query int false "Limit" default(20)
// @Success 200 {object} SuccessResponse{data=ListUsersHTTPResponse}
// @Failure 403 {object} ErrorResponse
// @Router /api/v1/admin/users [get]
func (h *AdminHandler) ListUsers(c fiber.Ctx) error {
	offset, _ := strconv.Atoi(c.Query("offset", "0"))
	limit, _ := strconv.Atoi(c.Query("limit", "20"))

	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	query := application.ListUsersQuery{Offset: offset, Limit: limit}
	result, err := h.listUsers.Execute(c.Context(), query)
	if err != nil {
		return err
	}

	users := make([]AdminUserResponse, len(result.Users))
	for i, u := range result.Users {
		users[i] = toAdminUserResponse(u)
	}

	return SendOK(c, "users listed", ListUsersHTTPResponse{
		Users:  users,
		Total:  result.Total,
		Offset: offset,
		Limit:  limit,
	})
}

// @Summary Get user by ID (admin)
// @Description Returns full user details including roles and status
// @Tags Admin - Users
// @Security ApiKeyAuth
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} SuccessResponse{data=AdminUserResponse}
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id} [get]
func (h *AdminHandler) AdminGetUser(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "user ID is required", nil)
	}

	user, err := h.getUser.Execute(c.Context(), id)
	if err != nil {
		return err
	}

	return SendOK(c, "user found", toAdminUserResponse(user))
}

// @Summary Assign role to user
// @Description Assigns a role to the specified user
// @Tags Admin - Users
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param request body AssignUserRoleRequest true "Role"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id}/roles [post]
func (h *AdminHandler) AssignUserRole(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "user ID is required", nil)
	}

	var req AssignUserRoleRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	cmd := application.AssignUserRoleCommand{
		UserID:   id,
		RoleName: req.RoleName,
	}

	if err := h.assignUserRole.Execute(c.Context(), cmd); err != nil {
		return err
	}

	return SendOK(c, "role assigned to user", nil)
}

// @Summary Revoke role from user
// @Description Removes a role from the specified user
// @Tags Admin - Users
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param request body RevokeUserRoleRequest true "Role"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id}/roles [delete]
func (h *AdminHandler) RevokeUserRole(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "user ID is required", nil)
	}

	var req RevokeUserRoleRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	cmd := application.RevokeUserRoleCommand{
		UserID:   id,
		RoleName: req.RoleName,
	}

	if err := h.revokeUserRole.Execute(c.Context(), cmd); err != nil {
		return err
	}

	return SendOK(c, "role revoked from user", nil)
}

// @Summary Activate user
// @Description Admin activates a user account
// @Tags Admin - Users
// @Security ApiKeyAuth
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} SuccessResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id}/activate [post]
func (h *AdminHandler) ActivateUser(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "user ID is required", nil)
	}

	if err := h.activateUser.Execute(c.Context(), id); err != nil {
		return err
	}

	return SendOK(c, "user activated", nil)
}

// @Summary Deactivate user
// @Description Admin deactivates a user account
// @Tags Admin - Users
// @Security ApiKeyAuth
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} SuccessResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id}/deactivate [post]
func (h *AdminHandler) DeactivateUser(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "user ID is required", nil)
	}

	if err := h.deactivateUser.Execute(c.Context(), id); err != nil {
		return err
	}

	return SendOK(c, "user deactivated", nil)
}

// @Summary Delete user (soft)
// @Description Admin soft-deletes a user and revokes all sessions
// @Tags Admin - Users
// @Security ApiKeyAuth
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} SuccessResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id} [delete]
func (h *AdminHandler) DeleteUser(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "user ID is required", nil)
	}

	if err := h.deleteUser.Execute(c.Context(), id); err != nil {
		return err
	}

	return SendOK(c, "user deleted", nil)
}

// --- Seed & Token Validation ---

// @Summary Seed roles
// @Description Seeds roles from the YAML configuration file
// @Tags Admin - Seed
// @Security ApiKeyAuth
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/admin/seed/roles [post]
func (h *AdminHandler) SeedRoles(c fiber.Ctx) error {
	if err := h.seedRoles.Execute(c.Context()); err != nil {
		return err
	}

	return SendOK(c, "roles seeded successfully", nil)
}

// @Summary Validate access token
// @Description Validates an access token and returns the associated user info (service-to-service)
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ValidateTokenRequest true "Token"
// @Success 200 {object} SuccessResponse{data=ValidateTokenResponse}
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/auth/validate [post]
func (h *AdminHandler) ValidateToken(c fiber.Ctx) error {
	var req ValidateTokenRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	query := application.ValidateAccessQuery{
		AccessToken: req.AccessToken,
	}

	access, err := h.validateAccess.Execute(c.Context(), query)
	if err != nil {
		return err
	}

	return SendOK(c, "token is valid", ValidateTokenResponse{
		UserID:    access.UserID,
		SessionID: access.SessionID,
		Roles:     access.Roles,
	})
}

// --- Mappers ---

func toRoleHTTPResponse(r application.RoleReadModel) RoleHTTPResponse {
	return RoleHTTPResponse{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Permissions: r.Permissions,
	}
}

func toAdminUserResponse(u application.UserReadModel) AdminUserResponse {
	return AdminUserResponse{
		ID:           u.ID,
		Email:        u.Email,
		IsActive:     u.IsActive,
		Roles:        u.Roles,
		RegisteredAt: u.RegisteredAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:    u.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}
