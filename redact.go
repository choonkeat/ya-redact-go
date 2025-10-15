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
func Redact[T any](arg T, isSensitive func(string) bool, redactValue func(any) any) T {
	var zero T
	if reflect.ValueOf(arg).Kind() == reflect.Invalid {
		return zero
	}

	v := reflect.ValueOf(arg)
	result := redactReflectValue(v, isSensitive, redactValue).Interface()
	return result.(T)
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

func redactReflectValue(v reflect.Value, isSensitive func(string) bool, redactValue func(any) any) reflect.Value {
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
		redacted := redactReflectValue(elem, isSensitive, redactValue)
		ptr := reflect.New(redacted.Type())
		ptr.Elem().Set(redacted)
		return ptr

	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		// Redact the underlying value and wrap it back in an interface
		elem := v.Elem()
		redacted := redactReflectValue(elem, isSensitive, redactValue)
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

				if fieldIsSensitive && field.CanInterface() {
					// Field is sensitive - apply redaction callback
					// Special handling for pointer types: dereference, redact, then re-wrap
					if field.Kind() == reflect.Ptr && !field.IsNil() {
						elem := field.Elem()
						if elem.CanInterface() {
							originalValue := elem.Interface()
							redactedValue := redactValue(originalValue)
							redactedReflect := reflect.ValueOf(redactedValue)

							// Create a new pointer to the redacted value
							if redactedReflect.Type().AssignableTo(elem.Type()) {
								ptr := reflect.New(redactedReflect.Type())
								ptr.Elem().Set(redactedReflect)
								result.Field(i).Set(ptr)
							} else {
								// Type mismatch - recursively process instead
								redacted := redactReflectValue(field, isSensitive, redactValue)
								result.Field(i).Set(redacted)
							}
						}
					} else {
						// Non-pointer sensitive field
						originalValue := field.Interface()
						redactedValue := redactValue(originalValue)

						// Set the redacted value back
						redactedReflect := reflect.ValueOf(redactedValue)
						if redactedReflect.Type().AssignableTo(field.Type()) {
							result.Field(i).Set(redactedReflect)
						} else {
							// Type mismatch - recursively process instead
							redacted := redactReflectValue(field, isSensitive, redactValue)
							result.Field(i).Set(redacted)
						}
					}
				} else {
					// For non-sensitive fields, recursively process
					redacted := redactReflectValue(field, isSensitive, redactValue)
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

			if keyStr != "" && isSensitive(keyStr) && value.CanInterface() {
				// Redact the value for sensitive keys
				originalValue := value.Interface()
				redactedValue := redactValue(originalValue)
				result.SetMapIndex(key, reflect.ValueOf(redactedValue))
			} else {
				// For non-sensitive keys, recursively process the value
				redacted := redactReflectValue(value, isSensitive, redactValue)
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
			redacted := redactReflectValue(elem, isSensitive, redactValue)
			result.Index(i).Set(redacted)
		}
		return result

	case reflect.Array:
		// Create a new array with redacted elements
		result := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			elem := v.Index(i)
			redacted := redactReflectValue(elem, isSensitive, redactValue)
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
