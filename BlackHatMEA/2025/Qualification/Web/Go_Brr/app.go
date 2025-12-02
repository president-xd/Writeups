package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
)

type User struct {
	Username string `json:"username" xml:"username"`
	Password string `json:"password" xml:"password"`
	IsAdmin  bool   `json:"-"  xml:"-,omitempty"`
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	var user User

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read body", http.StatusBadRequest)
		return
	}

	
	if err := xml.Unmarshal(body, &user); err != nil {
		fmt.Println("XML unmarshal failed, trying JSON:", err)
		if err := json.Unmarshal(body, &user); err != nil {
			http.Error(w, "Invalid data format (not XML or JSON)", http.StatusBadRequest)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if user.IsAdmin {
		w.Write([]byte(`"Authorized"`))
	} else {
		w.Write([]byte(`"Not Authorized"`))
	}
}

func main() {
	http.HandleFunc("/user", userHandler)
	fmt.Println("Server running on 0.0.0.0:8082")
	http.ListenAndServe("0.0.0.0:8082", nil)
}
