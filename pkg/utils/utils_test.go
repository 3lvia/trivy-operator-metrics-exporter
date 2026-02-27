package utils

import (
	"os"
	"testing"
)

func TestTernary(t *testing.T) {
	result1 := Ternary(true, "yes", "no")
	if result1 != "yes" {
		t.Errorf("Expected 'yes', got %v", result1)
	}

	result2 := Ternary(false, 42, 100)
	if result2 != 100 {
		t.Errorf("Expected 100, got %v", result2)
	}
}

func TestGetEnvFallback(t *testing.T) {
	const (
		envKey        = "TEST_ENV_KEY"
		fallbackValue = "default_value"
	)

	// Test when the environment variable is not set
	err := os.Unsetenv(envKey)
	if err != nil {
		t.Fatalf("Failed to unset environment variable: %v", err)
	}

	result1 := GetEnvFallback(envKey, fallbackValue)
	if result1 != fallbackValue {
		t.Errorf("Expected fallback value '%s', got '%s'", fallbackValue, result1)
	}

	// Test when the environment variable is set
	expectedValue := "actual_value"

	err = os.Setenv(envKey, expectedValue)
	if err != nil {
		t.Fatalf("Failed to set environment variable: %v", err)
	}

	result2 := GetEnvFallback(envKey, fallbackValue)
	if result2 != expectedValue {
		t.Errorf("Expected environment value '%s', got '%s'", expectedValue, result2)
	}

	// Clean up
	err = os.Unsetenv(envKey)
	if err != nil {
		t.Fatalf("Failed to unset environment variable: %v", err)
	}
}
