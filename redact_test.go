package yaredact

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	// Helper functions
	isSensitive := func(name string) bool {
		lower := strings.ToLower(name)
		return lower == "password" || lower == "secret" || lower == "apikey" || lower == "token"
	}

	redactValue := func(v any) any {
		if _, ok := v.(string); ok {
			return "***REDACTED***"
		}
		return v
	}

	t.Run("Standalone String", func(t *testing.T) {
		result := Redact("sensitive data", isSensitive, redactValue)
		if result != "sensitive data" {
			t.Errorf("Expected standalone string to remain unchanged, got %v", result)
		}
	})

	t.Run("Simple Struct", func(t *testing.T) {
		type User struct {
			Name     string
			Password string
			Age      int
		}

		user := User{
			Name:     "John",
			Password: "secret123",
			Age:      25,
		}

		result := Redact(user, isSensitive, redactValue)

		if result.Name != "John" {
			t.Errorf("Expected Name to be 'John', got %s", result.Name)
		}
		if result.Password != "***REDACTED***" {
			t.Errorf("Expected Password to be redacted, got %s", result.Password)
		}
		if result.Age != 25 {
			t.Errorf("Expected Age to be 25, got %d", result.Age)
		}
	})

	t.Run("Nested Struct", func(t *testing.T) {
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
			Cred: Credentials{
				Token:  "abc123",
				Secret: "xyz789",
			},
		}

		result := Redact(service, isSensitive, redactValue)

		if result.Name != "API Service" {
			t.Errorf("Expected Name to be 'API Service', got %s", result.Name)
		}
		if result.Cred.Token != "***REDACTED***" {
			t.Errorf("Expected Token to be redacted, got %s", result.Cred.Token)
		}
		if result.Cred.Secret != "***REDACTED***" {
			t.Errorf("Expected Secret to be redacted, got %s", result.Cred.Secret)
		}
	})

	t.Run("Map with Sensitive Keys", func(t *testing.T) {
		data := map[string]string{
			"name":     "John",
			"password": "secret123",
			"email":    "john@example.com",
		}

		result := Redact[map[string]string](data, isSensitive, redactValue)

		if result["name"] != "John" {
			t.Errorf("Expected name to be 'John', got %s", result["name"])
		}
		if result["password"] != "***REDACTED***" {
			t.Errorf("Expected password to be redacted, got %s", result["password"])
		}
		if result["email"] != "john@example.com" {
			t.Errorf("Expected email to be 'john@example.com', got %s", result["email"])
		}
	})

	t.Run("Slice of Structs", func(t *testing.T) {
		type User struct {
			Name   string
			Secret string
		}

		users := []User{
			{Name: "Alice", Secret: "alice-secret"},
			{Name: "Bob", Secret: "bob-secret"},
		}

		result := Redact[[]User](users, isSensitive, redactValue)

		if len(result) != 2 {
			t.Fatalf("Expected 2 users, got %d", len(result))
		}

		for i, user := range result {
			if user.Name != users[i].Name {
				t.Errorf("Expected Name[%d] to be %s, got %s", i, users[i].Name, user.Name)
			}
			if user.Secret != "***REDACTED***" {
				t.Errorf("Expected Secret[%d] to be redacted, got %s", i, user.Secret)
			}
		}
	})

	t.Run("Complex Nested Structure", func(t *testing.T) {
		type Config struct {
			Settings map[string]interface{}
		}

		config := Config{
			Settings: map[string]interface{}{
				"theme":    "dark",
				"apikey":   "key123",
				"password": "pass456",
				"nested": map[string]string{
					"public": "data",
					"token":  "tok789",
				},
			},
		}

		result := Redact(config, isSensitive, redactValue)
		settings := result.Settings

		if settings["theme"] != "dark" {
			t.Errorf("Expected theme to be 'dark', got %v", settings["theme"])
		}
		if settings["apikey"] != "***REDACTED***" {
			t.Errorf("Expected apikey to be redacted, got %v", settings["apikey"])
		}
		if settings["password"] != "***REDACTED***" {
			t.Errorf("Expected password to be redacted, got %v", settings["password"])
		}

		nested := settings["nested"].(map[string]string)
		if nested["public"] != "data" {
			t.Errorf("Expected nested.public to be 'data', got %s", nested["public"])
		}
		if nested["token"] != "***REDACTED***" {
			t.Errorf("Expected nested.token to be redacted, got %s", nested["token"])
		}
	})

	t.Run("Pointers", func(t *testing.T) {
		type User struct {
			Name     *string
			Password *string
		}

		name := "John"
		pass := "secret"

		user := User{
			Name:     &name,
			Password: &pass,
		}

		result := Redact(user, isSensitive, redactValue)

		if *result.Name != "John" {
			t.Errorf("Expected Name to be 'John', got %s", *result.Name)
		}
		if *result.Password != "***REDACTED***" {
			t.Errorf("Expected Password to be redacted, got %s", *result.Password)
		}

		// Verify original values are unchanged
		if *user.Name != "John" {
			t.Errorf("Original Name was modified")
		}
		if *user.Password != "secret" {
			t.Errorf("Original Password was modified")
		}
	})

	t.Run("Struct Tags JSON", func(t *testing.T) {
		type User struct {
			Name   string `json:"username"`
			APIKey string `json:"api_key"`
			Secret string `json:"secret_token"`
			Age    int    `json:"user_age"`
		}

		user := User{
			Name:   "John",
			APIKey: "sk-12345",
			Secret: "mysecret",
			Age:    25,
		}

		// Sensitive check includes both field names and json tags
		customIsSensitive := func(name string) bool {
			lower := strings.ToLower(name)
			return lower == "api_key" || strings.Contains(lower, "secret") || strings.Contains(lower, "token")
		}

		result := Redact(user, customIsSensitive, redactValue)

		if result.Name != "John" {
			t.Errorf("Expected Name to be 'John', got %s", result.Name)
		}
		if result.APIKey != "***REDACTED***" {
			t.Errorf("Expected APIKey to be redacted (matched by json tag 'api_key'), got %s", result.APIKey)
		}
		if result.Secret != "***REDACTED***" {
			t.Errorf("Expected Secret to be redacted (matched by field name and json tag), got %s", result.Secret)
		}
		if result.Age != 25 {
			t.Errorf("Expected Age to be 25, got %d", result.Age)
		}
	})

	t.Run("Struct Tags XML", func(t *testing.T) {
		type Config struct {
			PublicKey  string `xml:"publicKey"`
			PrivateKey string `xml:"privateKey"`
			AuthToken  string `xml:"token"`
			Version    string `xml:"version"`
		}

		config := Config{
			PublicKey:  "pub123",
			PrivateKey: "priv456",
			AuthToken:  "auth789",
			Version:    "1.0.0",
		}

		// Check for "key" and "token" in XML tags
		customIsSensitive := func(name string) bool {
			lower := strings.ToLower(name)
			return strings.Contains(lower, "privatekey") || lower == "token"
		}

		result := Redact(config, customIsSensitive, redactValue)

		if result.PublicKey != "pub123" {
			t.Errorf("Expected PublicKey to remain unchanged, got %s", result.PublicKey)
		}
		if result.PrivateKey != "***REDACTED***" {
			t.Errorf("Expected PrivateKey to be redacted (matched by xml tag), got %s", result.PrivateKey)
		}
		if result.AuthToken != "***REDACTED***" {
			t.Errorf("Expected AuthToken to be redacted (matched by xml tag), got %s", result.AuthToken)
		}
		if result.Version != "1.0.0" {
			t.Errorf("Expected Version to be '1.0.0', got %s", result.Version)
		}
	})

	t.Run("Struct Tags with Options", func(t *testing.T) {
		type Request struct {
			ID       string `json:"id,omitempty"`
			Password string `json:"password,omitempty"`
			Data     string `json:"data"`
			Ignored  string `json:"-"`
		}

		req := Request{
			ID:       "123",
			Password: "secret",
			Data:     "somedata",
			Ignored:  "ignored",
		}

		result := Redact(req, isSensitive, redactValue)

		if result.ID != "123" {
			t.Errorf("Expected ID to be '123', got %s", result.ID)
		}
		if result.Password != "***REDACTED***" {
			t.Errorf("Expected Password to be redacted (tag name before comma), got %s", result.Password)
		}
		if result.Data != "somedata" {
			t.Errorf("Expected Data to be 'somedata', got %s", result.Data)
		}
		if result.Ignored != "ignored" {
			t.Errorf("Expected Ignored to be 'ignored', got %s", result.Ignored)
		}
	})

	t.Run("Multiple Tag Types", func(t *testing.T) {
		type Record struct {
			Username string `json:"user" xml:"username" yaml:"user_name"`
			APIKey   string `json:"key" xml:"apiKey" form:"api_key"`
			DBPass   string `db:"password"`
		}

		record := Record{
			Username: "alice",
			APIKey:   "xyz789",
			DBPass:   "dbsecret",
		}

		// Sensitive if contains "key" or "password" in any tag
		customIsSensitive := func(name string) bool {
			lower := strings.ToLower(name)
			return strings.Contains(lower, "key") || strings.Contains(lower, "password")
		}

		result := Redact(record, customIsSensitive, redactValue)

		if result.Username != "alice" {
			t.Errorf("Expected Username to be 'alice', got %s", result.Username)
		}
		if result.APIKey != "***REDACTED***" {
			t.Errorf("Expected APIKey to be redacted (has 'key' in multiple tags), got %s", result.APIKey)
		}
		if result.DBPass != "***REDACTED***" {
			t.Errorf("Expected DBPass to be redacted (has 'password' in db tag), got %s", result.DBPass)
		}
	})

	t.Run("Nil Values", func(t *testing.T) {
		type User struct {
			Name     *string
			Password *string
		}

		user := User{
			Name:     nil,
			Password: nil,
		}

		result := Redact(user, isSensitive, redactValue)

		if result.Name != nil {
			t.Errorf("Expected Name to remain nil")
		}
		if result.Password != nil {
			t.Errorf("Expected Password to remain nil")
		}
	})
}
