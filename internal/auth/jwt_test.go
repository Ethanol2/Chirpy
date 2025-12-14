package auth

// Unit tests writen by gemini

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJWTFlow(t *testing.T) {
	// Setup test data
	userID := uuid.New()
	secret := "my-very-secure-test-secret"
	duration := 5 * time.Minute

	// Test case: Successful creation and validation
	t.Run("Create and Validate Success", func(t *testing.T) {
		token, err := MakeJWT(userID, secret, duration)
		if err != nil {
			t.Fatalf("Failed to make JWT: %v", err)
		}

		parsedID, err := ValidateJWT(token, secret)
		if err != nil {
			t.Fatalf("Failed to validate JWT: %v", err)
		}

		if parsedID != userID {
			t.Errorf("Expected userID %v, got %v", userID, parsedID)
		}
	})

	// Test case: Validation failure with incorrect secret
	t.Run("Invalid Secret Failure", func(t *testing.T) {
		token, _ := MakeJWT(userID, secret, duration)
		_, err := ValidateJWT(token, "wrong-secret")
		if err == nil {
			t.Error("Expected error when validating with wrong secret, but got none")
		}
	})

	// Test case: Expiration handling
	t.Run("Expired Token Failure", func(t *testing.T) {
		// Create a token that expires instantly (negative duration can be used for testing)
		expiredToken, _ := MakeJWT(userID, secret, -time.Second)

		_, err := ValidateJWT(expiredToken, secret)
		if err == nil {
			t.Error("Expected error for expired token, but got none")
		}
	})
}
func TestGetBearerToken(t *testing.T) {
	// Define a slice of test cases (table-driven testing)
	tests := []struct {
		name          string
		headers       http.Header
		expectedToken string
		expectedError error
	}{
		{
			name: "Valid Bearer Token",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123xyz"},
			},
			expectedToken: "abc123xyz",
			expectedError: nil,
		},
		{
			name:    "Missing Authorization Header",
			headers: http.Header{
				// Empty headers map simulates a missing header
			},
			expectedToken: "",
			expectedError: ErrMissingHeader,
		},
		{
			name: "Incorrect Scheme (Basic Auth)",
			headers: http.Header{
				"Authorization": []string{"Basic userpass"},
			},
			expectedToken: "",
			expectedError: ErrMissingBearerText,
		},
		{
			name: "Malformed Header (Missing Token)",
			headers: http.Header{
				"Authorization": []string{"Bearer "}, // Space but no token
			},
			expectedToken: "",
			expectedError: ErrInvalidFormat,
		},
		{
			name: "Malformed Header (One Part)",
			headers: http.Header{
				"Authorization": []string{"justonetoken"},
			},
			expectedToken: "",
			expectedError: ErrInvalidFormat,
		},
		{
			name: "Multiple Authorization Headers (Should take first)",
			headers: http.Header{
				"Authorization": []string{"Bearer firsttoken", "Bearer secondtoken"},
			},
			expectedToken: "firsttoken", // http.Header.Get() returns only the first value
			expectedError: nil,
		},
	}

	// Iterate over the test cases and run the test logic
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotToken, gotError := GetBearerToken(tt.headers)

			// Check for expected token value
			if gotToken != tt.expectedToken {
				t.Errorf("GetBearerToken() gotToken = %v, want %v", gotToken, tt.expectedToken)
			}

			// Check for expected error type
			if gotError != tt.expectedError {
				// We use errors.Is for robust error comparison
				if !errors.Is(gotError, tt.expectedError) {
					t.Errorf("GetBearerToken() gotError = %v, want %v", gotError, tt.expectedError)
				}
			}

			// Ensure we don't return an error when we expect nil, and vice-versa
			if (gotError == nil) != (tt.expectedError == nil) {
				t.Errorf("GetBearerToken() error mismatch: got %v, want %v", gotError, tt.expectedError)
			}
		})
	}
}
