package services

import (
	"Desires/utils"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

func CreateSession(sessionID string, user *User) string {

	sessionJSON, _ := json.Marshal(user)

	// Check if sessions folder exists, create it if it doesn't
	folderPath := filepath.Join("/tmp/sessions/", user.Username)
	if _, err := os.Stat(folderPath); os.IsNotExist(err) {
		if err := os.MkdirAll(folderPath, 0755); err != nil {
			log.Fatal(err)
		}
	}

	// Write session file
	sessionFilePath := filepath.Join(folderPath, sessionID)
	err := os.WriteFile(sessionFilePath, sessionJSON, 0644)
	if err != nil {
		log.Fatal(err)
	}

	return sessionID
}

func PrepareSession(sessionID string, username string) error {
	return utils.RedisClient.Set(username, sessionID, 0)
}

func GetSession(username string) (*User, error) {
	sessionID, err := utils.RedisClient.Get(username)
	if err != nil {
		return nil, err
	}
	sessionJSON, err := os.ReadFile(filepath.Join("/tmp/sessions", username, sessionID))
	if err != nil {
		return nil, err
	}
	var session User
	err = json.Unmarshal(sessionJSON, &session)

	if err != nil {
		return nil, err
	}
	return &session, nil
}
