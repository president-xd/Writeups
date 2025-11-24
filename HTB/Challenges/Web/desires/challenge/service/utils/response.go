package utils

import (
	"github.com/gofiber/fiber/v2"
)

type MsgResp struct {
	Message string `json:"message"`
}
type ErrResp struct {
	Err string `json:"error"`
}

func MessageResponse(ctx *fiber.Ctx, msg string, statusCode int) error {
	return ctx.Status(statusCode).JSON(MsgResp{msg})
}

func ErrorResponse(ctx *fiber.Ctx, msg string, statusCode int) error {
	return ctx.Status(statusCode).JSON(ErrResp{msg})
}
