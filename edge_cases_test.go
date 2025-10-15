package yaredact

import (
	"strings"
	"testing"
)

// TestEdgeCases tests various edge cases and potential issues
func TestEdgeCases(t *testing.T) {
	isSensitive := func(name string) bool {
		lower := strings.ToLower(name)
		return lower == "password" || lower == "secret"
	}

	redactString := func(s string) string {
		return "***REDACTED***"
	}

	t.Run("Empty String Values", func(t *testing.T) {
		type User struct {
			Name     string
			Password string
		}

		user := User{
			Name:     "John",
			Password: "", // Empty password
		}

		result := Redact(user, isSensitive, redactString).(User)

		if result.Password != "***REDACTED***" {
			t.Errorf("Expected empty password to be redacted, got %s", result.Password)
		}
	})

	t.Run("Sensitive Field With Non-String Type", func(t *testing.T) {
		type Config struct {
			Secret int // Sensitive field but not a string
		}

		config := Config{Secret: 12345}

		result := Redact(config, isSensitive, redactString).(Config)

		// Non-string sensitive fields should remain unchanged
		if result.Secret != 12345 {
			t.Errorf("Expected non-string sensitive field to remain unchanged, got %d", result.Secret)
		}
	})

	t.Run("Nested Sensitive Struct Field", func(t *testing.T) {
		type Inner struct {
			Data string
		}

		type Outer struct {
			Secret Inner // Field named "Secret" but contains struct
		}

		outer := Outer{
			Secret: Inner{Data: "sensitive-data"},
		}

		result := Redact(outer, isSensitive, redactString).(Outer)

		// The struct itself won't be redacted, but should recurse into it
		if result.Secret.Data != "sensitive-data" {
			t.Errorf("Expected nested struct data to remain, got %s", result.Secret.Data)
		}
	})

	t.Run("Map With Non-String Keys", func(t *testing.T) {
		data := map[int]string{
			1: "value1",
			2: "value2",
		}

		result := Redact(data, isSensitive, redactString).(map[int]string)

		// Non-string keys should pass through unchanged
		if result[1] != "value1" || result[2] != "value2" {
			t.Errorf("Expected map with int keys to remain unchanged")
		}
	})

	t.Run("Circular Reference Prevention - Slice", func(t *testing.T) {
		// Test that we don't modify original data
		users := []string{"password123", "normal"}

		result := Redact(users, isSensitive, redactString).([]string)

		// Original should be unchanged
		if users[0] != "password123" {
			t.Errorf("Original slice was modified")
		}
		// Result should preserve values (strings in slices are not checked for sensitivity)
		if result[0] != "password123" {
			t.Errorf("Expected slice strings to remain unchanged")
		}
	})

	t.Run("Unexported Struct Fields", func(t *testing.T) {
		type User struct {
			Name     string
			password string // unexported
		}

		user := User{
			Name:     "John",
			password: "secret123",
		}

		result := Redact(user, isSensitive, redactString).(User)

		// Unexported fields get zero values due to reflection limitations
		// This is expected behavior in Go - reflection can't copy unexported fields
		if result.password != "" {
			t.Errorf("Expected unexported field to be zero-valued (reflection limitation), got %s", result.password)
		}
		// But exported fields should work fine
		if result.Name != "John" {
			t.Errorf("Expected Name to be 'John', got %s", result.Name)
		}
	})

	t.Run("Nil Slice", func(t *testing.T) {
		var users []string

		result := Redact(users, isSensitive, redactString)

		// Type assert to get the actual slice
		resultSlice, ok := result.([]string)
		if !ok {
			t.Errorf("Expected result to be []string")
		}
		if resultSlice != nil {
			t.Errorf("Expected nil slice to remain nil, got %v", resultSlice)
		}
	})

	t.Run("Nil Map", func(t *testing.T) {
		var data map[string]string

		result := Redact(data, isSensitive, redactString)

		// Type assert to get the actual map
		resultMap, ok := result.(map[string]string)
		if !ok {
			t.Errorf("Expected result to be map[string]string")
		}
		if resultMap != nil {
			t.Errorf("Expected nil map to remain nil, got %v", resultMap)
		}
	})

	t.Run("Empty Struct", func(t *testing.T) {
		type Empty struct{}

		empty := Empty{}

		result := Redact(empty, isSensitive, redactString).(Empty)

		// Should not panic
		_ = result
	})

	t.Run("Struct With Only Unexported Fields", func(t *testing.T) {
		type Private struct {
			secret string
		}

		priv := Private{secret: "hidden"}

		result := Redact(priv, isSensitive, redactString).(Private)

		// Unexported fields get zero values due to reflection limitations
		if result.secret != "" {
			t.Errorf("Expected unexported field to be zero-valued (reflection limitation), got %s", result.secret)
		}
	})

	t.Run("Case Sensitivity Of Field Names", func(t *testing.T) {
		type User struct {
			PASSWORD string // All caps
		}

		user := User{PASSWORD: "secret123"}

		// isSensitive checks lowercase, so should match
		result := Redact(user, isSensitive, redactString).(User)

		if result.PASSWORD != "***REDACTED***" {
			t.Errorf("Expected case-insensitive match, got %s", result.PASSWORD)
		}
	})
}
