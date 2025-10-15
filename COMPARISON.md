# Go Redaction Libraries Comparison

## Overview Comparison

| Feature | ya-redact-go | ucarion/redact | ssrathi/go-scrub | cockroachdb/redact |
|---------|------------------|----------------|------------------|-------------------|
| **Approach** | Functional, non-mutating | Path-based mutation | Field name-based scrubbing | Safe/unsafe markers |
| **Mutates Original** | No ✅ | Yes ⚠️ | Yes ⚠️ | No ✅ |
| **Returns New Value** | Yes ✅ | No | No | Yes (RedactableString) |
| **Custom Predicates** | Yes ✅ | No | Partial | No |
| **Primary Use Case** | Generic redaction | Simple field redaction | Pre-logging scrubbing | CockroachDB logging |

## API Usage Comparison

### ya-redact-go
```go
// Define custom predicates
isSensitive := func(name string) bool {
    return strings.ToLower(name) == "password"
}
redactString := func(s string) string {
    return "***REDACTED***"
}

// Usage - returns new value
user := User{Name: "John", Password: "secret"}
redacted := Redact(user, isSensitive, redactString).(User)
// Original 'user' is unchanged
```

### github.com/ucarion/redact
```go
import "github.com/ucarion/redact"

// Path-based redaction
user := User{Name: "John", Password: "secret"}
redact.Redact([]string{"Password"}, &user)
// 'user' is now mutated: {Name: "John", Password: ""}

// For nested structs
req := Request{User: User{Password: "secret"}}
redact.Redact([]string{"User", "Password"}, &req)
```

### github.com/ssrathi/go-scrub
```go
import "github.com/ssrathi/go-scrub"

// Field name-based scrubbing
user := User{Name: "John", Password: "secret"}
fieldsToScrub := map[string]bool{
    "password": true,  // case-insensitive
}

// Returns JSON string, mutates original
jsonStr := scrub.Scrub(&user, fieldsToScrub)
// Returns: {"Name":"John","Password":"********"}
```

### github.com/cockroachdb/redact
```go
import "github.com/cockroachdb/redact"

// Using Safe/Unsafe wrappers
msg := redact.Sprintf("User %s has password %s", 
    redact.Safe("john"),     // Won't be redacted
    "secret123")              // Will be redacted

// Output with markers: "User john has password ‹secret123›"
fmt.Println(msg.StripMarkers())  // "User john has password secret123"
fmt.Println(msg.Redact())        // "User john has password ‹×›"

// For custom types, implement SafeFormatter
type User struct {
    Name     string
    Password string
}

func (u User) SafeFormat(p redact.SafePrinter, verb rune) {
    p.Printf("User{Name:%s Password:%s}", 
        redact.Safe(u.Name), 
        u.Password)  // Unsafe by default
}
```

## Feature Comparison

| Feature | ya-redact-go | ucarion/redact | ssrathi/go-scrub | cockroachdb/redact |
|---------|------------------|----------------|------------------|-------------------|
| **Structs** | ✅ Full support | ✅ Full support | ✅ Full support | ✅ Via SafeFormatter |
| **Maps** | ✅ Full support | ✅ Limited* | ✅ Full support | ❌ Manual only |
| **Slices/Arrays** | ✅ Full support | ✅ Full support | ✅ Full support | ✅ In Printf context |
| **Pointers** | ✅ Full support | ✅ Full support | ✅ Full support | ✅ Full support |
| **Nested Structures** | ✅ Recursive | ✅ Path-based | ✅ Recursive | ✅ Via SafeFormatter |
| **Field Name Matching** | ✅ Custom function | ❌ Exact paths | ✅ Case-insensitive | ❌ Not applicable |
| **Redaction Strategy** | ✅ Custom function | ❌ Empty string | ❌ Fixed "********" | ❌ Fixed markers |
| **Standalone Strings** | ✅ Passthrough | ❌ Not applicable | ❌ Not applicable | ✅ In Printf context |
| **Interface Support** | ✅ Full support | ⚠️ Limited | ⚠️ Limited | ✅ SafeFormatter |

*ucarion/redact has limitations with maps - cannot mutate map elements directly, requires pointer values

## Dependencies

| Library | Direct Dependencies | Indirect Dependencies | Go Version |
|---------|-------------------|---------------------|------------|
| **ya-redact-go** | None (stdlib only) | None | 1.22+ |
| **ucarion/redact** | None (stdlib only) | None | 1.13+ |
| **ssrathi/go-scrub** | None (stdlib only) | None | 1.13+ |
| **cockroachdb/redact** | • bufbuild/buf<br>• cockroachdb/gostdlib<br>• cockroachdb/logtags<br>• kr/pretty<br>• kr/text<br>• stretchr/testify | Multiple protobuf-related<br>and testing dependencies | 1.19+ |

## Performance Characteristics

| Library | Performance Impact | Memory Allocation |
|---------|-------------------|------------------|
| **ya-redact-go** | Moderate - creates new values | New allocation for each redacted structure |
| **ucarion/redact** | Fast - in-place mutation | Minimal - mutates existing |
| **ssrathi/go-scrub** | Moderate - reflection + JSON | JSON marshaling overhead |
| **cockroachdb/redact** | Fast for logging | String buffer allocations |

## When to Use Each

### Use ya-redact-go when:
- You need non-mutating behavior (functional programming style)
- You require custom sensitivity detection logic
- You want custom redaction strategies (hashing, partial masking, etc.)
- You need to preserve original data
- You want zero external dependencies

### Use ucarion/redact when:
- You're okay with in-place mutation
- You have simple path-based redaction needs
- You want minimal overhead
- You don't need custom redaction logic
- ⚠️ Note: Project appears inactive

### Use ssrathi/go-scrub when:
- You need JSON output for logging
- You want case-insensitive field matching
- You're okay with fixed redaction patterns
- You need simple field-name-based scrubbing

### Use cockroachdb/redact when:
- You're building sophisticated logging systems
- You need fine-grained control over safe/unsafe data
- You want to integrate with CockroachDB ecosystem
- You need production-grade, well-tested solution
- You're okay with more dependencies