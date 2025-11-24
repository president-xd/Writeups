package main

import (
	"Desires/services"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
)

func main() {

	engine := html.New("./views", ".html")
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	app.Static("/static", "./static")

	authenticatedGroup := app.Group("/user", services.SessionMiddleware)

	app.Get("/register", services.ViewRegister)
	app.Get("/", services.ViewLogin)
	app.Post("/register", services.RegisterHandler)
	app.Post("/login", services.LoginHandler)

	// Upload an archive
	authenticatedGroup.Post("/upload", services.UploadEnigma)
	authenticatedGroup.Get("/upload", services.ViewUpload)
	authenticatedGroup.Get("/admin", services.DesireIsEnigma)

	log.Fatal(app.Listen(":1337"))
}
