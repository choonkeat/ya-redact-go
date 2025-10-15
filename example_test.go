package yaredact_test

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/choonkeat/ya-redact-go"
)

// Example demonstrates basic usage of the Redact function
func Example() {
	type User struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	user := User{
		Name:     "John Doe",
		Password: "secret123",
		Email:    "john@example.com",
	}

	// Define what's sensitive
	isSensitive := func(name string) bool {
		lower := strings.ToLower(name)
		return lower == "password" || lower == "secret"
	}

	// Define how to redact
	redactValue := func(v any) any {
		if _, ok := v.(string); ok {
			return "***REDACTED***"
		}
		return v
	}

	// Redact and get new value
	redacted := yaredact.Redact(user, isSensitive, redactValue)

	fmt.Printf("%+v\n", redacted)
	// Output: {Name:John Doe Password:***REDACTED*** Email:john@example.com}
}

// Example_structTags demonstrates struct tag support
func Example_structTags() {
	type APIResponse struct {
		UserName    string `json:"username"`
		AccessToken string `json:"access_token"` // Caught by json tag
		APIKey      string `json:"api_key"`      // Caught by json tag
	}

	response := APIResponse{
		UserName:    "alice",
		AccessToken: "token123",
		APIKey:      "key456",
	}

	isSensitive := func(name string) bool {
		lower := strings.ToLower(name)
		return lower == "access_token" ||
			lower == "api_key" ||
			strings.Contains(lower, "token")
	}

	redactValue := func(v any) any {
		if _, ok := v.(string); ok {
			return "***REDACTED***"
		}
		return v
	}

	redacted := yaredact.Redact(response, isSensitive, redactValue)
	fmt.Printf("%+v\n", redacted)
	// Output: {UserName:alice AccessToken:***REDACTED*** APIKey:***REDACTED***}
}

// Example_nestedStructures demonstrates redacting nested structs
func Example_nestedStructures() {
	type Credentials struct {
		Token  string
		Secret string
	}

	type Service struct {
		Name string
		Cred Credentials
	}

	service := Service{
		Name: "API Service",
		Cred: Credentials{Token: "abc123", Secret: "xyz789"},
	}

	isSensitive := func(name string) bool {
		lower := strings.ToLower(name)
		return strings.Contains(lower, "token") || strings.Contains(lower, "secret")
	}

	redactValue := func(v any) any {
		if _, ok := v.(string); ok {
			return "***REDACTED***"
		}
		return v
	}

	redacted := yaredact.Redact(service, isSensitive, redactValue)
	fmt.Printf("%+v\n", redacted)
	// Output: {Name:API Service Cred:{Token:***REDACTED*** Secret:***REDACTED***}}
}

// Example_maps demonstrates redacting sensitive map keys
func Example_maps() {
	data := map[string]string{
		"name":     "John",
		"password": "secret123",
		"email":    "john@example.com",
	}

	isSensitive := func(name string) bool {
		return strings.ToLower(name) == "password"
	}

	redactValue := func(v any) any {
		if _, ok := v.(string); ok {
			return "***REDACTED***"
		}
		return v
	}

	redacted := yaredact.Redact[map[string]string](data, isSensitive, redactValue)

	// Print in a predictable order for testing
	fmt.Printf("email: %s\n", redacted["email"])
	fmt.Printf("name: %s\n", redacted["name"])
	fmt.Printf("password: %s\n", redacted["password"])
	// Output:
	// email: john@example.com
	// name: John
	// password: ***REDACTED***
}

// Example_partialRedaction demonstrates custom redaction showing last 4 characters
func Example_partialRedaction() {
	type User struct {
		Name     string
		Password string
		APIKey   string
	}

	user := User{
		Name:     "Jane Smith",
		Password: "mypassword123",
		APIKey:   "sk-proj-abc123def456",
	}

	isSensitive := func(name string) bool {
		lower := strings.ToLower(name)
		return lower == "password" || lower == "apikey"
	}

	// Partial redaction - show last 4 characters
	partialRedact := func(v any) any {
		if s, ok := v.(string); ok {
			if len(s) <= 4 {
				return "****"
			}
			return "****" + s[len(s)-4:]
		}
		return v
	}

	redacted := yaredact.Redact(user, isSensitive, partialRedact)
	fmt.Printf("%+v\n", redacted)
	// Output: {Name:Jane Smith Password:****d123 APIKey:****f456}
}

// Example_hashRedaction demonstrates hash-based redaction
func Example_hashRedaction() {
	type Config struct {
		PublicSetting string
		Secret        string
	}

	config := Config{
		PublicSetting: "enabled",
		Secret:        "my-secret-value",
	}

	isSensitive := func(name string) bool {
		return strings.ToLower(name) == "secret"
	}

	// Hash-based redaction
	hashRedact := func(v any) any {
		if s, ok := v.(string); ok {
			h := sha256.Sum256([]byte(s))
			return fmt.Sprintf("sha256:%x", h[:8])
		}
		return v
	}

	redacted := yaredact.Redact(config, isSensitive, hashRedact)
	fmt.Printf("PublicSetting: %s\n", redacted.PublicSetting)
	fmt.Printf("Secret starts with: sha256:\n")
	fmt.Printf("Secret is hashed: %t\n", strings.HasPrefix(redacted.Secret, "sha256:"))
	// Output:
	// PublicSetting: enabled
	// Secret starts with: sha256:
	// Secret is hashed: true
}

// Example_patternBasedDetection demonstrates flexible pattern-based sensitivity detection
func Example_patternBasedDetection() {
	type Credentials struct {
		Username      string
		Password      string
		AccessToken   string
		RefreshToken  string
		PublicKey     string
		PrivateKey    string
		SessionCookie string
	}

	creds := Credentials{
		Username:      "admin",
		Password:      "pass123",
		AccessToken:   "at_abc",
		RefreshToken:  "rt_xyz",
		PublicKey:     "pub_key",
		PrivateKey:    "priv_key",
		SessionCookie: "cookie_data",
	}

	// Pattern-based detection
	isSensitive := func(name string) bool {
		lower := strings.ToLower(name)
		patterns := []string{"password", "secret", "token", "private", "cookie"}
		for _, p := range patterns {
			if strings.Contains(lower, p) {
				return true
			}
		}
		return false
	}

	redactValue := func(v any) any {
		if _, ok := v.(string); ok {
			return "[REDACTED]"
		}
		return v
	}

	redacted := yaredact.Redact(creds, isSensitive, redactValue)
	fmt.Printf("Username: %s\n", redacted.Username)
	fmt.Printf("Password: %s\n", redacted.Password)
	fmt.Printf("AccessToken: %s\n", redacted.AccessToken)
	fmt.Printf("RefreshToken: %s\n", redacted.RefreshToken)
	fmt.Printf("PublicKey: %s\n", redacted.PublicKey)
	fmt.Printf("PrivateKey: %s\n", redacted.PrivateKey)
	fmt.Printf("SessionCookie: %s\n", redacted.SessionCookie)
	// Output:
	// Username: admin
	// Password: [REDACTED]
	// AccessToken: [REDACTED]
	// RefreshToken: [REDACTED]
	// PublicKey: pub_key
	// PrivateKey: [REDACTED]
	// SessionCookie: [REDACTED]
}

// Example_suffixBasedDetection demonstrates suffix-based sensitivity detection
func Example_suffixBasedDetection() {
	type APIConfig struct {
		ServiceName     string
		DatabaseKey     string
		AuthToken       string
		CacheTimeout    int
		SecretSignature string
	}

	config := APIConfig{
		ServiceName:     "my-service",
		DatabaseKey:     "db_key_123",
		AuthToken:       "bearer_token",
		CacheTimeout:    300,
		SecretSignature: "sig_xyz",
	}

	// Suffix-based detection
	isSensitive := func(name string) bool {
		lower := strings.ToLower(name)
		return strings.HasSuffix(lower, "key") ||
			strings.HasSuffix(lower, "token") ||
			strings.HasPrefix(lower, "secret") ||
			strings.Contains(lower, "signature")
	}

	redactValue := func(v any) any {
		if _, ok := v.(string); ok {
			return "***"
		}
		return v
	}

	redacted := yaredact.Redact(config, isSensitive, redactValue)
	fmt.Printf("ServiceName: %s\n", redacted.ServiceName)
	fmt.Printf("DatabaseKey: %s\n", redacted.DatabaseKey)
	fmt.Printf("AuthToken: %s\n", redacted.AuthToken)
	fmt.Printf("CacheTimeout: %d\n", redacted.CacheTimeout)
	fmt.Printf("SecretSignature: %s\n", redacted.SecretSignature)
	// Output:
	// ServiceName: my-service
	// DatabaseKey: ***
	// AuthToken: ***
	// CacheTimeout: 300
	// SecretSignature: ***
}
