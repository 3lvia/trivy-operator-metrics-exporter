package appconfig

import (
	"testing"
	"time"
)

func TestParseTimeWithDefault(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		defaultValue string
		expected     string
		expectError  bool
	}{
		{
			name:         "Valid duration string",
			value:        "10s",
			defaultValue: "5s",
			expected:     "10s",
			expectError:  false,
		},
		{
			name:         "Empty value uses default",
			value:        "",
			defaultValue: "5s",
			expected:     "5s",
			expectError:  false,
		},
		{
			name:         "Invalid duration string",
			value:        "invalid",
			defaultValue: "5s",
			expected:     "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaultDuration, err := time.ParseDuration(tt.defaultValue)
			if err != nil {
				t.Fatalf("Failed to parse default duration: %v", err)
			}

			result, err := parseTimeWithDefault(tt.value, defaultDuration)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				expectedDur, _ := time.ParseDuration(tt.expected)
				if result != expectedDur {
					t.Errorf("Expected %v, got %v", expectedDur, result)
				}
			}
		})
	}
}
