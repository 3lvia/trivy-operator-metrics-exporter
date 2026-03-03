package appconfig

import (
	"testing"
	"time"
)

func TestParseTimeWithDefault(t *testing.T) {
	t.Parallel()

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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			defaultDuration, err := time.ParseDuration(test.defaultValue)
			if err != nil {
				t.Fatalf("Failed to parse default duration: %v", err)
			}

			result, err := parseTimeWithDefault(test.value, defaultDuration)
			if test.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				expectedDur, _ := time.ParseDuration(test.expected)
				if result != expectedDur {
					t.Errorf("Expected %v, got %v", expectedDur, result)
				}
			}
		})
	}
}
