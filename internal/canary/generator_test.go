package canary

import (
	"strings"
	"testing"
)

func TestGenerateAWSKey(t *testing.T) {
	tok := GenerateAWSKey("dev-canary-01")

	if !strings.HasPrefix(tok.KeyID, "AKIA") {
		t.Fatalf("expected KeyID starting with AKIA, got %s", tok.KeyID)
	}

	if len(tok.KeyID) != 20 {
		t.Fatalf("expected KeyID length 20, got %d (%s)", len(tok.KeyID), tok.KeyID)
	}

	if !VerifySignature(tok.KeyID) {
		t.Fatalf("expected valid canary signature on key %s", tok.KeyID)
	}

	if VerifySignature("AKIA_INVALID_TEST") {
		t.Fatalf("expected false on invalid key")
	}
}
