package auth

// Unit tests writen by gemini

import (
	"testing"
)

// Test hashing and verification for correct passwords (table-driven test).
func TestPasswordHashing(t *testing.T) {
	// Define test cases using a slice of structs.
	var tests = []struct {
		name     string
		password string
		valid    bool // Indicates if the password should be valid
	}{
		{"Valid password", "securepassword123", true},
		{"Short password", "short", true}, // Should still hash and verify correctly
		{"Special chars", "p@ssw0rd!", true},
		{"Empty password (handled by application logic typically, but should hash)", "", true},
		{"Wrong password (negative test case)", "wrongpassword", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Hash the password (simulating user registration)
			hash, err := HashPassword(tt.password)
			if err != nil {
				t.Fatalf("HashPassword failed: %v", err)
			}

			// Step 2: Verify the password (simulating user login attempt)
			match, err := CheckPasswordHash(tt.password, hash)
			if err != nil {
				t.Fatalf("VerifyPassword failed: %v", err)
			}

			// Step 3: Assertions
			if tt.valid {
				if !match {
					t.Errorf("Expected valid password to match hash, but it didn't")
				}
			} else {
				// We need a separate test case for invalid passwords as we can't test "wrong" input
				// within the same flow of hashing and then verifying the original plain text password.
				// This case is handled in the TestVerifyWrongPassword below.
			}
		})
	}
}

// Test for specific negative scenario where a wrong password is provided for an existing hash.
func TestVerifyWrongPassword(t *testing.T) {
	correctPassword := "correcthorsebatterystaple"
	wrongPassword := "incorrectpassword"

	// Hash the correct password first.
	hash, err := HashPassword(correctPassword)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Try verifying with the wrong password.
	match, err := CheckPasswordHash(wrongPassword, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed unexpectedly: %v", err)
	}

	if match {
		t.Errorf("Expected wrong password to not match hash, but it did")
	}
}

// Test that different salts are generated for the same password.
func TestSaltsAreUnique(t *testing.T) {
	password := "samepassword"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword 1 failed: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword 2 failed: %v", err)
	}

	if hash1 == hash2 {
		t.Errorf("Two hashes for the same password and random salt should be different")
	}
}

// Example of a benchmark test to measure the performance of the hashing function.
func BenchmarkHashPassword(b *testing.B) {
	password := "some-test-password"
	for i := 0; i < b.N; i++ {
		HashPassword(password)
	}
}
