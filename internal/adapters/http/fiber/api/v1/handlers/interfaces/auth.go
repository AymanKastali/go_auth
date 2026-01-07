package interfaces

import "github.com/gofiber/fiber/v2"

type ILoginHandler interface {
	Execute(c *fiber.Ctx) error
}

type ILogoutHandler interface {
	Execute(c *fiber.Ctx) error
}

type IRefreshTokenHandler interface {
	Execute(c *fiber.Ctx) error
}

type IRegisterHandler interface {
	Execute(c *fiber.Ctx) error
}

type IUpdateRoleHandler interface {
	Execute(c *fiber.Ctx) error
}
