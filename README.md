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
```

## API

### Redact

```go
func Redact[T any](
    arg T,
    isSensitive func(string) bool,
    redactValue func(any) any,
) T
```

Recursively processes data structures and redacts sensitive fields/keys.

**Parameters:**
- `T`: The type parameter (inferred from arg)
- `arg`: The value to redact (struct, map, slice, pointer, etc.)
- `isSensitive`: Function that returns true if a field/key name is sensitive
- `redactValue`: Function that transforms sensitive values (receives any type, returns any type)

**Returns:** A new value of the same type `T` with sensitive data redacted

**Type Safety:** With generics, no type assertion needed - the return type matches the input type automatically.

**Type Inference:** Go infers the type parameter from the argument, so you can simply call `Redact(user, ...)` instead of `Redact[User](user, ...)`. The explicit type parameter syntax is available if needed for clarity.

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
// Output: {UserName:alice AccessToken:***REDACTED*** APIKey:***REDACTED***}
```

### Nested Structures

```go
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
// Output: {Name:API Service Cred:{Token:***REDACTED*** Secret:***REDACTED***}}
```

### Maps with Sensitive Keys

```go
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
// Output: map[email:john@example.com name:John password:***REDACTED***]
```

### Custom Redaction Strategies

#### Partial Redaction

Show last 4 characters for debugging while keeping data mostly hidden:

```go
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
// Output: {Name:Jane Smith Password:****d123 APIKey:****f456}
```

#### Hash-Based Redaction

Use hashing for auditing while maintaining privacy:

```go
import "crypto/sha256"

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

hashRedact := func(v any) any {
    if s, ok := v.(string); ok {
        h := sha256.Sum256([]byte(s))
        return fmt.Sprintf("sha256:%x", h[:8])
    }
    return v
}

redacted := yaredact.Redact(config, isSensitive, hashRedact)
// Output: {PublicSetting:enabled Secret:sha256:3c6e0b8a9c15224a}
```

### Flexible Sensitivity Detection

#### Pattern-Based Detection

Match fields containing specific keywords:

```go
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
// Output: Username:admin, Password:[REDACTED], AccessToken:[REDACTED],
//         RefreshToken:[REDACTED], PublicKey:pub_key, PrivateKey:[REDACTED],
//         SessionCookie:[REDACTED]
```

#### Suffix-Based Detection

Match fields by suffix patterns:

```go
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
// Output: {ServiceName:my-service DatabaseKey:*** AuthToken:*** CacheTimeout:300 SecretSignature:***}
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
