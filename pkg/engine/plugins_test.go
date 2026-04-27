package engine

import (
	"os"
	"testing"
)

// TestPluginMatcher verifies Lua matcher plugin functionality
func TestPluginMatcher(t *testing.T) {
	// Create a test Lua script
	script := `
function match(response)
    return response.status_code == 200 and response.size > 100
end
`
	tmpfile, err := os.CreateTemp("", "test_matcher_*.lua")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(script)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	// Load plugin
	matcher, err := NewPluginMatcher(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer matcher.Close()

	// Test matching
	tests := []struct {
		statusCode int
		size       int
		expected   bool
	}{
		{200, 150, true},  // Should match
		{200, 50, false},  // Size too small
		{404, 150, false}, // Wrong status code
		{500, 50, false},  // Both wrong
	}

	for _, tt := range tests {
		result := matcher.Match(tt.statusCode, tt.size, 0, 0, "test body", "text/html")
		if result != tt.expected {
			t.Errorf("Match(status=%d, size=%d) = %v, want %v",
				tt.statusCode, tt.size, result, tt.expected)
		}
	}
}

// TestPluginMutator verifies Lua mutator plugin functionality
func TestPluginMutator(t *testing.T) {
	// Create a test Lua script
	script := `
function mutate(original)
    local variants = {}
    table.insert(variants, original)
    table.insert(variants, original .. ".bak")
    table.insert(variants, string.upper(original))
    return variants
end
`
	tmpfile, err := os.CreateTemp("", "test_mutator_*.lua")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(script)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	// Load plugin
	mutator, err := NewPluginMutator(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to create plugin: %v", err)
	}
	defer mutator.Close()

	// Test mutation
	original := "admin"
	variants := mutator.Mutate(original)

	expected := []string{"admin", "admin.bak", "ADMIN"}
	if len(variants) != len(expected) {
		t.Errorf("Expected %d variants, got %d", len(expected), len(variants))
	}

	for i, want := range expected {
		if i >= len(variants) || variants[i] != want {
			t.Errorf("Variant %d: got %q, want %q", i, variants[i], want)
		}
	}
}

// TestPluginMatcherError verifies error handling
func TestPluginMatcherError(t *testing.T) {
	// Try to load non-existent file
	_, err := NewPluginMatcher("/nonexistent/file.lua")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Try to load script without match function
	script := `
function wrong_name()
    return true
end
`
	tmpfile, err := os.CreateTemp("", "test_no_match_*.lua")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(script)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	_, err = NewPluginMatcher(tmpfile.Name())
	if err == nil {
		t.Error("Expected error for missing match function")
	}
}

// TestPluginMutatorError verifies error handling
func TestPluginMutatorError(t *testing.T) {
	// Try to load non-existent file
	_, err := NewPluginMutator("/nonexistent/file.lua")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Try to load script without mutate function
	script := `
function wrong_name()
    return {}
end
`
	tmpfile, err := os.CreateTemp("", "test_no_mutate_*.lua")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(script)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	_, err = NewPluginMutator(tmpfile.Name())
	if err == nil {
		t.Error("Expected error for missing mutate function")
	}
}
