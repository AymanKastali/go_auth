package fiberapp

import (
	"go_auth/internal/application"
	"go_auth/internal/application/command"
	"go_auth/internal/application/query"
	"strconv"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
)

type AdminController struct {
	validate         *validator.Validate
	listRoles        query.IListRolesHandler
	getRole          query.IGetRoleHandler
	createRole       command.ICreateRoleHandler
	assignPermission command.IAssignPermissionHandler
	revokePermission command.IRevokePermissionHandler
	listUsers        query.IListUsersHandler
	getUser          query.IGetUserByIDHandler
	assignUserRole   command.IAssignUserRoleHandler
	revokeUserRole   command.IRevokeUserRoleHandler
	activateUser     command.IAdminActivateUserHandler
	deactivateUser   command.IAdminDeactivateUserHandler
	deleteUser       command.IAdminDeleteUserHandler
	seedRoles        command.ISeedRolesHandler
}

func NewAdminController(
	validate *validator.Validate,
	listRoles query.IListRolesHandler,
	getRole query.IGetRoleHandler,
	createRole command.ICreateRoleHandler,
	assignPermission command.IAssignPermissionHandler,
	revokePermission command.IRevokePermissionHandler,
	listUsers query.IListUsersHandler,
	getUser query.IGetUserByIDHandler,
	assignUserRole command.IAssignUserRoleHandler,
	revokeUserRole command.IRevokeUserRoleHandler,
	activateUser command.IAdminActivateUserHandler,
	deactivateUser command.IAdminDeactivateUserHandler,
	deleteUser command.IAdminDeleteUserHandler,
	seedRoles command.ISeedRolesHandler,
) *AdminController {
	return &AdminController{
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
	}
}

func (h *AdminController) RegisterRoutes(admin fiber.Router) {
	// Role management
	admin.Get("/roles", h.ListRoles)
	admin.Get("/roles/:id", h.GetRole)
	admin.Post("/roles", h.CreateRole)
	admin.Post("/roles/:id/permissions", h.AssignPermission)
	admin.Delete("/roles/:id/permissions", h.RevokePermission)

	// User management
	admin.Get("/users", h.ListUsers)
	admin.Get("/users/:id", h.AdminGetUser)
	admin.Post("/users/:id/roles", h.AssignUserRole)
	admin.Delete("/users/:id/roles", h.RevokeUserRole)
	admin.Post("/users/:id/activate", h.ActivateUser)
	admin.Post("/users/:id/deactivate", h.DeactivateUser)
	admin.Delete("/users/:id", h.DeleteUser)

	// Seeding
	admin.Post("/seed/roles", h.SeedRoles)
}

// --- Role Endpoints ---

// @Summary List all roles
// @Description Returns all roles with their permissions
// @Tags Admin - Roles
// @Security AccessToken
// @Produce json
// @Success 200 {object} DataResponse{data=[]RoleHTTPResponse}
// @Failure 403 {object} ErrorResponse
// @Router /api/v1/admin/roles [get]
func (h *AdminController) ListRoles(c fiber.Ctx) error {
	roles, err := h.listRoles.Handle(c.Context())
	if err != nil {
		return err
	}

	resp := make([]RoleHTTPResponse, len(roles))
	for i, r := range roles {
		resp[i] = toRoleHTTPResponse(r)
	}

	return SendOK(c, resp)
}

// @Summary Get role by ID
// @Description Returns a single role with its permissions
// @Tags Admin - Roles
// @Security AccessToken
// @Produce json
// @Param id path string true "Role ID"
// @Success 200 {object} DataResponse{data=RoleHTTPResponse}
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/roles/{id} [get]
func (h *AdminController) GetRole(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "role ID is required")
	}

	role, err := h.getRole.Handle(c.Context(), id)
	if err != nil {
		return err
	}

	return SendOK(c, toRoleHTTPResponse(role))
}

// @Summary Create a new role
// @Description Creates a role with optional permissions
// @Tags Admin - Roles
// @Security AccessToken
// @Accept json
// @Produce json
// @Param request body CreateRoleRequest true "Role Details"
// @Success 201 {object} DataResponse{data=RoleHTTPResponse}
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Router /api/v1/admin/roles [post]
func (h *AdminController) CreateRole(c fiber.Ctx) error {
	var req CreateRoleRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	cmd := command.CreateRoleCommand{
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
	}

	role, err := h.createRole.Handle(c.Context(), cmd)
	if err != nil {
		return err
	}

	return SendCreated(c, toRoleHTTPResponse(role))
}

// @Summary Assign permission to role
// @Description Adds a permission to an existing role
// @Tags Admin - Roles
// @Security AccessToken
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Param request body AssignPermissionRequest true "Permission"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/roles/{id}/permissions [post]
func (h *AdminController) AssignPermission(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "role ID is required")
	}

	var req AssignPermissionRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	cmd := command.AssignPermissionCommand{
		RoleID:     id,
		Permission: req.Permission,
	}

	if err := h.assignPermission.Handle(c.Context(), cmd); err != nil {
		return err
	}

	return SendNoContent(c)
}

// @Summary Revoke permission from role
// @Description Removes a permission from an existing role
// @Tags Admin - Roles
// @Security AccessToken
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Param request body RevokePermissionRequest true "Permission"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/roles/{id}/permissions [delete]
func (h *AdminController) RevokePermission(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "role ID is required")
	}

	var req RevokePermissionRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	cmd := command.RevokePermissionCommand{
		RoleID:     id,
		Permission: req.Permission,
	}

	if err := h.revokePermission.Handle(c.Context(), cmd); err != nil {
		return err
	}

	return SendNoContent(c)
}

// --- User Endpoints ---

// @Summary List users (paginated)
// @Description Returns a paginated list of users
// @Tags Admin - Users
// @Security AccessToken
// @Produce json
// @Param offset query int false "Offset" default(0)
// @Param limit query int false "Limit" default(20)
// @Success 200 {object} DataResponse{data=ListUsersHTTPResponse}
// @Failure 403 {object} ErrorResponse
// @Router /api/v1/admin/users [get]
func (h *AdminController) ListUsers(c fiber.Ctx) error {
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

	q := query.ListUsersQuery{Offset: offset, Limit: limit}
	result, err := h.listUsers.Handle(c.Context(), q)
	if err != nil {
		return err
	}

	users := make([]AdminUserResponse, len(result.Users))
	for i, u := range result.Users {
		users[i] = toAdminUserResponse(u)
	}

	return SendOK(c, ListUsersHTTPResponse{
		Users:  users,
		Total:  result.Total,
		Offset: offset,
		Limit:  limit,
	})
}

// @Summary Get user by ID (admin)
// @Description Returns full user details including roles and status
// @Tags Admin - Users
// @Security AccessToken
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} DataResponse{data=AdminUserResponse}
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id} [get]
func (h *AdminController) AdminGetUser(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "user ID is required")
	}

	user, err := h.getUser.Handle(c.Context(), id)
	if err != nil {
		return err
	}

	return SendOK(c, toAdminUserResponse(user))
}

// @Summary Assign role to user
// @Description Assigns a role to the specified user
// @Tags Admin - Users
// @Security AccessToken
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param request body AssignUserRoleRequest true "Role"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id}/roles [post]
func (h *AdminController) AssignUserRole(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "user ID is required")
	}

	var req AssignUserRoleRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	cmd := command.AssignUserRoleCommand{
		UserID:   id,
		RoleName: req.RoleName,
	}

	if err := h.assignUserRole.Handle(c.Context(), cmd); err != nil {
		return err
	}

	return SendNoContent(c)
}

// @Summary Revoke role from user
// @Description Removes a role from the specified user
// @Tags Admin - Users
// @Security AccessToken
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param request body RevokeUserRoleRequest true "Role"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id}/roles [delete]
func (h *AdminController) RevokeUserRole(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "user ID is required")
	}

	var req RevokeUserRoleRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	cmd := command.RevokeUserRoleCommand{
		UserID:   id,
		RoleName: req.RoleName,
	}

	if err := h.revokeUserRole.Handle(c.Context(), cmd); err != nil {
		return err
	}

	return SendNoContent(c)
}

// @Summary Activate user
// @Description Admin activates a user account
// @Tags Admin - Users
// @Security AccessToken
// @Produce json
// @Param id path string true "User ID"
// @Success 204 "No Content"
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id}/activate [post]
func (h *AdminController) ActivateUser(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "user ID is required")
	}

	if err := h.activateUser.Handle(c.Context(), id); err != nil {
		return err
	}

	return SendNoContent(c)
}

// @Summary Deactivate user
// @Description Admin deactivates a user account
// @Tags Admin - Users
// @Security AccessToken
// @Produce json
// @Param id path string true "User ID"
// @Success 204 "No Content"
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id}/deactivate [post]
func (h *AdminController) DeactivateUser(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "user ID is required")
	}

	if err := h.deactivateUser.Handle(c.Context(), id); err != nil {
		return err
	}

	return SendNoContent(c)
}

// @Summary Delete user (soft)
// @Description Admin soft-deletes a user and revokes all sessions
// @Tags Admin - Users
// @Security AccessToken
// @Produce json
// @Param id path string true "User ID"
// @Success 204 "No Content"
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/admin/users/{id} [delete]
func (h *AdminController) DeleteUser(c fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return SendBadRequest(c, "user ID is required")
	}

	if err := h.deleteUser.Handle(c.Context(), id); err != nil {
		return err
	}

	return SendNoContent(c)
}

// --- Seed ---

// @Summary Seed roles
// @Description Seeds roles from the YAML configuration file
// @Tags Admin - Seed
// @Security AccessToken
// @Produce json
// @Success 204 "No Content"
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/admin/seed/roles [post]
func (h *AdminController) SeedRoles(c fiber.Ctx) error {
	if err := h.seedRoles.Handle(c.Context()); err != nil {
		return err
	}

	return SendNoContent(c)
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
