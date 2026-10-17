package mongostore

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// These tests need no database. They cover the cryptographic properties the
// transient-URL store depends on, so the properties are asserted directly
// against the AEAD rather than inferred from a passing round trip.
//
// MongoDB-dependent behaviour is covered by the integration suite.

// testAEAD returns a throwaway AES-GCM cipher. Its key protects nothing.
func testAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	aead, err := NewTransientURLCipher([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatalf("NewTransientURLCipher: %v", err)
	}
	return aead
}

func freshNonce(t *testing.T, aead cipher.AEAD) []byte {
	t.Helper()
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}
	return nonce
}

func TestNewTransientURLCipherRejectsShortKeys(t *testing.T) {
	t.Parallel()

	// A short key is rejected rather than stretched: a silently weakened key is
	// worse than a startup failure.
	for _, n := range []int{0, 1, 16, 31} {
		if _, err := NewTransientURLCipher(make([]byte, n)); !errors.Is(err, ErrEncryptionKeyInvalid) {
			t.Errorf("key of %d bytes: err = %v, want ErrEncryptionKeyInvalid", n, err)
		}
	}
	if _, err := NewTransientURLCipher(make([]byte, 32)); err != nil {
		t.Errorf("32-byte key rejected: %v", err)
	}
}

// AES-256-GCM must use a 96-bit nonce; a different size would mean the store's
// stored nonces were incompatible with the cipher.
func TestCipherUses96BitNonce(t *testing.T) {
	t.Parallel()

	if got := testAEAD(t).NonceSize(); got != 12 {
		t.Errorf("NonceSize = %d, want 12 (96-bit GCM nonce)", got)
	}
}

// Reusing a nonce under one key destroys GCM's authentication guarantee for
// both records, so the store must draw a fresh one per record.
func TestNoncesAreNotRepeated(t *testing.T) {
	t.Parallel()

	aead := testAEAD(t)
	seen := make(map[string]bool, 512)

	for i := 0; i < 512; i++ {
		n := freshNonce(t, aead)
		key := string(n)
		if seen[key] {
			t.Fatal("a nonce repeated across 512 draws")
		}
		seen[key] = true
	}
}

// Two records for different scans must not decrypt interchangeably: the scan ID
// is the additional authenticated data.
func TestAADBindingRejectsCiphertextSwap(t *testing.T) {
	t.Parallel()

	aead := testAEAD(t)
	nonce := freshNonce(t, aead)
	sealed := aead.Seal(nil, nonce, []byte("https://example.test/login"), []byte("scan_A"))

	if _, err := aead.Open(nil, nonce, sealed, []byte("scan_A")); err != nil {
		t.Fatalf("correct scan ID failed to open: %v", err)
	}
	if _, err := aead.Open(nil, nonce, sealed, []byte("scan_B")); err == nil {
		t.Error("ciphertext opened under a different scan ID; the AAD is not binding")
	}
}

// Tampering must be detected rather than silently decrypted into garbage.
func TestTamperIsDetected(t *testing.T) {
	t.Parallel()

	aead := testAEAD(t)
	nonce := freshNonce(t, aead)
	sealed := aead.Seal(nil, nonce, []byte("https://example.test/login"), []byte("scan_A"))

	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[len(tampered)-1] ^= 0x01

	if _, err := aead.Open(nil, nonce, tampered, []byte("scan_A")); err == nil {
		t.Error("tampered ciphertext authenticated successfully")
	}
}

func TestWrongKeyCannotOpenARecord(t *testing.T) {
	t.Parallel()

	good, err := NewTransientURLCipher([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatalf("NewTransientURLCipher: %v", err)
	}
	other, err := NewTransientURLCipher([]byte(strings.Repeat("z", 32)))
	if err != nil {
		t.Fatalf("NewTransientURLCipher: %v", err)
	}

	nonce := freshNonce(t, good)
	sealed := good.Seal(nil, nonce, []byte("https://example.test/"), []byte("scan_A"))

	if _, err := other.Open(nil, nonce, sealed, []byte("scan_A")); err == nil {
		t.Error("a record opened under the wrong key")
	}
}

// ------------------------------------------------------- structural privacy

// bsonTags returns the BSON field names of a struct, following embedded
// structs. Used to assert the models cannot hold a raw URL or a key.
func bsonTags(v any) []string {
	rt := reflect.TypeOf(v)
	var tags []string

	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := f.Tag.Get("bson")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		tags = append(tags, name)
	}
	return tags
}

func transientBsonTags() []string {
	return bsonTags(transientURL{})
}

// A document must have no field capable of holding a raw URL or an API key.
// This is structural: the BSON tag does not exist, so a future refactor cannot
// start persisting one without adding the field and failing this test.
func TestModelsHaveNoRawURLOrKeyFields(t *testing.T) {
	t.Parallel()

	forbidden := []string{"url", "rawurl", "raw_url", "apikey", "api_key", "secret", "token", "password"}

	models := map[string][]string{
		"Scan":         bsonTags(Scan{}),
		"Assessment":   bsonTags(Assessment{}),
		"transientURL": transientBsonTags(),
	}

	for name, tags := range models {
		for _, tag := range tags {
			for _, bad := range forbidden {
				if strings.EqualFold(tag, bad) {
					t.Errorf("%s has field %q, which could hold a raw URL or a secret", name, tag)
				}
			}
		}
	}
}

// The provider job ID and submission ID must both be persisted, so a restarted
// worker can resume polling instead of submitting again.
func TestScanPersistsProviderIdentifiers(t *testing.T) {
	t.Parallel()

	tags := strings.Join(bsonTags(Scan{}), ",")
	for _, want := range []string{
		"provider", "provider_scan_id", "provider_submission_id",
		"provider_state", "provider_environment_id",
	} {
		if !strings.Contains(tags, want) {
			t.Errorf("Scan does not persist %q; fields are %s", want, tags)
		}
	}
}
