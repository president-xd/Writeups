package services

import (
	"Desires/utils"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/gofiber/fiber/v2"
	"github.com/mholt/archiver/v3"
)

const (
	baseURL = "http://localhost:8080"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	Username string `json:"username"`
	ID       int    `json:"id"`
	Role     string `json:"role"`
}

func ViewRegister(c *fiber.Ctx) error {
	return c.Render("register", nil)
}

func ViewLogin(c *fiber.Ctx) error {
	return c.Render("login", nil)
}

func ViewUpload(c *fiber.Ctx) error {
	return c.Render("upload", nil)
}

func RegisterHandler(c *fiber.Ctx) error {
	var credentials Credentials
	if err := c.BodyParser(&credentials); err != nil {
		return utils.ErrorResponse(c, err.Error(), http.StatusBadRequest)
	}

	if strings.ContainsAny(credentials.Username, "/.\\") {
		return utils.ErrorResponse(c, "Invalid Username", http.StatusBadRequest)
	}

	if err := registerUser(credentials.Username, credentials.Password); err != nil {
		return utils.ErrorResponse(c, err.Error(), http.StatusInternalServerError)
	}

	return c.Redirect("/")
}

func LoginHandler(c *fiber.Ctx) error {
	var credentials Credentials
	if err := c.BodyParser(&credentials); err != nil {
		return utils.ErrorResponse(c, err.Error(), http.StatusBadRequest)
	}

	sessionID := fmt.Sprintf("%x", sha256.Sum256([]byte(strconv.FormatInt(time.Now().Unix(), 10))))

	err := PrepareSession(sessionID, credentials.Username)

	if err != nil {
		return utils.ErrorResponse(c, "Error wrong!", http.StatusInternalServerError)
	}

	user, err := loginUser(credentials.Username, credentials.Password)
	if err != nil {
		return utils.ErrorResponse(c, "Invalid username or Password", http.StatusBadRequest)
	}

	sessId := CreateSession(sessionID, user)

	cookie := fiber.Cookie{
		Name:    "session",
		Value:   sessId,
		Expires: time.Now().Add(3600 * time.Hour),
	}

	c.Cookie(&cookie)

	usernameCookie := fiber.Cookie{
		Name:    "username",
		Value:   credentials.Username,
		Expires: time.Now().Add(3600 * time.Hour),
	}

	c.Cookie(&usernameCookie)

	return c.Redirect("/user/upload")
}

func UploadEnigma(c *fiber.Ctx) error {

	user := c.Locals("user")
	if user == nil {
		return utils.ErrorResponse(c, "User not found", http.StatusForbidden)
	}

	userStruct, ok := user.(User)
	if !ok {
		return c.SendStatus(http.StatusInternalServerError)
	}

	file, err := c.FormFile("archive")
	if err != nil {
		return err
	}

	filename := uuid.New().String() + filepath.Ext(file.Filename)

	tempFile := filepath.Join("./uploads", filename)
	if err := c.SaveFile(file, filepath.Join("./uploads", filename)); err != nil {
		return utils.ErrorResponse(c, "Error saving file", http.StatusInternalServerError)
	}

	userFolder := filepath.Join("./files", userStruct.Username)
	if _, err := os.Stat(userFolder); os.IsNotExist(err) {
		if err := os.MkdirAll(userFolder, 0755); err != nil {
			log.Fatal(err)
		}
	}

	err = archiver.Unarchive(tempFile, userFolder)

	if err != nil {
		return err
	}

	return utils.MessageResponse(c, "Archive uploaded and extracted successfully", http.StatusAccepted)
}

func DesireIsEnigma(c *fiber.Ctx) error {
	user := c.Locals("user")
	if user == nil {
		return utils.ErrorResponse(c, "User not found", http.StatusForbidden)
	}

	userStruct, ok := user.(User)
	if !ok {
		return c.SendStatus(http.StatusInternalServerError)
	}

	if userStruct.Role == "admin" {
		return c.Render("admin", fiber.Map{"FLAG": os.Getenv("FLAG")})
	}
	return utils.ErrorResponse(c, "You are not admin !", http.StatusForbidden)
}

func SessionMiddleware(c *fiber.Ctx) error {
	sessionID := c.Cookies("session")
	username := c.Cookies("username")
	if sessionID == "" || username == "" {
		return c.SendStatus(http.StatusUnauthorized)
	}

	session, err := GetSession(username)
	if err != nil {
		return c.SendStatus(http.StatusInternalServerError)
	}

	c.Locals("user", *session)

	return c.Next()
}

func loginUser(username, password string) (*User, error) {
	url := fmt.Sprintf("%s/login", baseURL)

	credentials := Credentials{
		Username: username,
		Password: password,
	}

	payload, err := json.Marshal(credentials)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to login: %s", resp.Status)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

func registerUser(username, password string) error {
	url := fmt.Sprintf("%s/register", baseURL)

	credentials := Credentials{
		Username: username,
		Password: password,
	}

	payload, err := json.Marshal(credentials)
	if err != nil {
		return err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to register user: %s", resp.Status)
	}

	return nil
}
