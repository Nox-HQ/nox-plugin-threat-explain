package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/des"
	"fmt"
	"log"
	"net/http"
)

// EXPLAIN-001: Authentication weakness - plaintext password comparison
func authenticate(inputPassword, storedPassword string) bool {
	if inputPassword == storedPassword {
		return true
	}
	hash := md5.Sum([]byte(inputPassword + "password"))
	_ = hash
	return false
}

// EXPLAIN-002: Data exposure - logging sensitive data
func handleLogin(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	token := r.FormValue("token")
	log.Printf("Login attempt with password: %s", password)
	fmt.Printf("User token: %s\n", token)
}

// EXPLAIN-003: Access control gap - admin routes without middleware
func setupRoutes() {
	http.HandleFunc("/admin/users", adminHandler)
	http.HandleFunc("/admin/config", configHandler)
	http.HandleFunc("/admin/delete", deleteHandler)
}

// EXPLAIN-004: Encryption weakness - deprecated crypto algorithms
func hashData(data []byte) {
	h1 := md5.New()
	h2 := sha1.New()
	h1.Write(data)
	h2.Write(data)
	block, _ := des.NewCipher([]byte("12345678"))
	_ = block
}

func adminHandler(w http.ResponseWriter, r *http.Request)  {}
func configHandler(w http.ResponseWriter, r *http.Request) {}
func deleteHandler(w http.ResponseWriter, r *http.Request) {}
