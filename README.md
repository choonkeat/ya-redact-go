# ya-redact-go

A flexible, zero-dependency Go library for redacting sensitive data in structs, maps, slices, and other data structures.

## Features

- **Non-mutating**: Returns new values, preserving originals
- **Flexible detection**: Custom sensitivity detection via user-defined functions
- **Struct tag aware**: Checks both field names and struct tags (`json`, `xml`, `yaml`, `form`, `query`, `db`, `bson`)
- **Custom redaction**: Define your own redaction strategy (masking, hashing, partial redaction, etc.)
- **Recursive processing**: Handles nested structs, maps, slices, arrays, pointers, and interfaces
- **Zero dependencies**: Uses only Go standard library

## Installation

```bash
go get github.com/choonkeat/ya-redact-go
```

## Quick Start

```go
package main

import (
    "fmt"
    "strings"
    "github.com/choonkeat/ya-redact-go"
)

type User struct {
    Name     string `json:"name"`
    Password string `json:"password"`
    Email    string `json:"email"`
}

func main() {
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
    redactString := func(s string) string {
        return "***REDACTED***"
    }

    // Redact and get new value
    redacted := yaredact.Redact(user, isSensitive, redactString).(User)

    fmt.Printf("%+v\n", redacted)
    // Output: {Name:John Doe Password:***REDACTED*** Email:john@example.com}
}
```

## API

### `Redact(arg any, isSensitive func(string) bool, redactString func(string) string) any`

Recursively processes data structures and redacts sensitive fields/keys.

**Parameters:**
- `arg`: The value to redact (struct, map, slice, pointer, etc.)
- `isSensitive`: Function that returns true if a field/key name is sensitive
- `redactString`: Function that transforms sensitive string values

**Returns:** A new value with sensitive data redacted

**Behavior:**
- **Structs**: Redacts fields matching `isSensitive` (checks both field names and struct tags)
- **Maps**: Redacts values for keys matching `isSensitive`
- **Slices/Arrays**: Recursively processes each element
- **Pointers**: Follows pointers and processes underlying values
- **Interfaces**: Unwraps and processes underlying values
- **Strings**: Returns as-is (standalone strings are not redacted)
- **Other types**: Returns as-is (int, float, bool, etc.)

## Examples

### Struct Tag Support

The function checks both Go field names and struct tags:

```go
type APIResponse struct {
    UserName     string `json:"username"`
    AccessToken  string `json:"access_token"`  // Caught by json tag
    APIKey       string `json:"api_key"`       // Caught by json tag
}

isSensitive := func(name string) bool {
    lower := strings.ToLower(name)
    return lower == "access_token" ||
           lower == "api_key" ||
           strings.Contains(lower, "token")
}
```

### Nested Structures

```go
type Service struct {
    Name string
    Cred Credentials
}

type Credentials struct {
    Token  string
    Secret string
}

service := Service{
    Name: "API Service",
    Cred: Credentials{Token: "abc123", Secret: "xyz789"},
}

redacted := yaredact.Redact(service, isSensitive, redactString).(Service)
// Both Token and Secret are redacted
```

### Maps with Sensitive Keys

```go
data := map[string]string{
    "name":     "John",
    "password": "secret123",
    "email":    "john@example.com",
}

redacted := yaredact.Redact(data, isSensitive, redactString).(map[string]string)
// redacted["password"] == "***REDACTED***"
```

### Custom Redaction Strategies

```go
// Partial redaction - show last 4 characters
redactString := func(s string) string {
    if len(s) <= 4 {
        return "****"
    }
    return "****" + s[len(s)-4:]
}

// Hash-based redaction
import "crypto/sha256"

redactString := func(s string) string {
    h := sha256.Sum256([]byte(s))
    return fmt.Sprintf("sha256:%x", h[:8])
}
```

### Flexible Sensitivity Detection

```go
// Pattern-based detection
isSensitive := func(name string) bool {
    lower := strings.ToLower(name)
    patterns := []string{"password", "secret", "token", "key", "credential"}
    for _, p := range patterns {
        if strings.Contains(lower, p) {
            return true
        }
    }
    return false
}

// Suffix-based detection
isSensitive := func(name string) bool {
    lower := strings.ToLower(name)
    return strings.HasSuffix(lower, "_key") ||
           strings.HasSuffix(lower, "_token") ||
           strings.HasPrefix(lower, "secret_")
}
```

## How It Works

The library uses reflection to traverse data structures and identify sensitive fields/keys based on your custom predicate function. When a sensitive field is found, it applies your custom redaction function to transform the value.

**Key behaviors:**
- Non-mutating: Always returns new values, original data is preserved
- Struct tags: Checks `json`, `xml`, `yaml`, `form`, `query`, `db`, `bson` tags
- Tag options: Correctly handles tag options like `json:"password,omitempty"`
- Recursive: Processes nested structures automatically

## Comparison with Other Libraries

See [COMPARISON.md](COMPARISON.md) for a detailed comparison with other Go redaction libraries.

## License

MIT License - see [LICENSE](LICENSE) file for details.
