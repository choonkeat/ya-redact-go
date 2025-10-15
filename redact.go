package yaredact

import (
	"reflect"
	"strings"
)

// Redact recursively processes data structures and redacts sensitive fields/keys
// - For strings: returns as-is (doesn't redact standalone strings)
// - For structs: redacts values of fields marked as sensitive (checking field names and json/xml/yaml/form/query/db/bson tags)
// - For maps: redacts values of keys marked as sensitive
// - For slices/arrays: recursively processes each element
// - For pointers: follows the pointer and processes the underlying value
func Redact(arg any, isSensitive func(string) bool, redactString func(string) string) any {
	if arg == nil {
		return nil
	}

	v := reflect.ValueOf(arg)
	return redactValue(v, isSensitive, redactString).Interface()
}

// isFieldSensitive checks if a struct field should be considered sensitive
// by examining both the field name and its struct tags (json, xml, yaml, etc.)
func isFieldSensitive(field reflect.StructField, isSensitive func(string) bool) bool {
	// Check the field name itself
	if isSensitive(field.Name) {
		return true
	}

	// Check common struct tags
	tagNames := []string{"json", "xml", "yaml", "form", "query", "db", "bson"}
	for _, tagName := range tagNames {
		if tagValue := field.Tag.Get(tagName); tagValue != "" {
			// Extract the actual name from the tag (before any comma-separated options)
			// e.g., "password,omitempty" -> "password"
			tagFieldName := strings.Split(tagValue, ",")[0]

			// Skip if it's a dash (which means ignore this field in marshaling)
			if tagFieldName == "-" {
				continue
			}

			// Check if this tag name indicates sensitivity
			if isSensitive(tagFieldName) {
				return true
			}
		}
	}

	return false
}

func redactValue(v reflect.Value, isSensitive func(string) bool, redactString func(string) string) reflect.Value {
	if !v.IsValid() {
		return v
	}

	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return v
		}
		// Create a new pointer to the redacted value
		elem := v.Elem()
		redacted := redactValue(elem, isSensitive, redactString)
		ptr := reflect.New(redacted.Type())
		ptr.Elem().Set(redacted)
		return ptr

	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		// Redact the underlying value and wrap it back in an interface
		elem := v.Elem()
		redacted := redactValue(elem, isSensitive, redactString)
		return redacted

	case reflect.Struct:
		// Create a new struct with redacted fields
		result := reflect.New(v.Type()).Elem()
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			fieldType := v.Type().Field(i)

			// Check if we can set this field (must be exported)
			if result.Field(i).CanSet() {
				// Check if field is sensitive by name or by struct tags
				fieldIsSensitive := isFieldSensitive(fieldType, isSensitive)

				if fieldIsSensitive {
					// If field is sensitive and is a string, redact it
					if field.Kind() == reflect.String {
						result.Field(i).SetString(redactString(field.String()))
					} else if field.Kind() == reflect.Ptr && !field.IsNil() && field.Elem().Kind() == reflect.String {
						// If field is a pointer to a string, redact the string value
						redactedStr := redactString(field.Elem().String())
						ptr := reflect.New(field.Elem().Type())
						ptr.Elem().SetString(redactedStr)
						result.Field(i).Set(ptr)
					} else {
						// For non-string sensitive fields, recursively redact
						redacted := redactValue(field, isSensitive, redactString)
						result.Field(i).Set(redacted)
					}
				} else {
					// For non-sensitive fields, recursively process
					redacted := redactValue(field, isSensitive, redactString)
					result.Field(i).Set(redacted)
				}
			}
		}
		return result

	case reflect.Map:
		if v.IsNil() {
			return v
		}
		// Create a new map with redacted values for sensitive keys
		result := reflect.MakeMap(v.Type())
		for _, key := range v.MapKeys() {
			value := v.MapIndex(key)

			// Check if the key is sensitive (convert key to string if possible)
			keyStr := ""
			if key.Kind() == reflect.String {
				keyStr = key.String()
			} else {
				// Try to convert key to string using fmt.Sprint equivalent
				if key.CanInterface() {
					keyStr = reflect.ValueOf(key.Interface()).String()
				}
			}

			if keyStr != "" && isSensitive(keyStr) {
				// Redact the value for sensitive keys
				if value.Kind() == reflect.String {
					result.SetMapIndex(key, reflect.ValueOf(redactString(value.String())))
				} else if value.Kind() == reflect.Interface && !value.IsNil() {
					// Handle interface{} values
					elem := value.Elem()
					if elem.Kind() == reflect.String {
						result.SetMapIndex(key, reflect.ValueOf(redactString(elem.String())))
					} else {
						redacted := redactValue(value, isSensitive, redactString)
						result.SetMapIndex(key, redacted)
					}
				} else {
					redacted := redactValue(value, isSensitive, redactString)
					result.SetMapIndex(key, redacted)
				}
			} else {
				// For non-sensitive keys, recursively process the value
				redacted := redactValue(value, isSensitive, redactString)
				result.SetMapIndex(key, redacted)
			}
		}
		return result

	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		// Create a new slice with redacted elements
		result := reflect.MakeSlice(v.Type(), v.Len(), v.Cap())
		for i := 0; i < v.Len(); i++ {
			elem := v.Index(i)
			redacted := redactValue(elem, isSensitive, redactString)
			result.Index(i).Set(redacted)
		}
		return result

	case reflect.Array:
		// Create a new array with redacted elements
		result := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			elem := v.Index(i)
			redacted := redactValue(elem, isSensitive, redactString)
			result.Index(i).Set(redacted)
		}
		return result

	case reflect.String:
		// Standalone strings are not redacted, return as-is
		return v

	default:
		// For other types (int, float, bool, etc.), return as-is
		return v
	}
}
