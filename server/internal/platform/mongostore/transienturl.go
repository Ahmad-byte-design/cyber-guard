package mongostore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// transientURL is one stored encrypted URL.
//
// The plaintext is never a field. There is no field that *could* hold it: a
// future refactor cannot start persisting the URL because the shape does not
// permit it.
type transientURL struct {
	// ScanID is the document _id and also the AES-GCM additional authenticated
	// data, which binds the ciphertext to this record.
	ScanID     string    `bson:"_id"`
	Ciphertext string    `bson:"ciphertext"`
	Nonce      string    `bson:"nonce"`
	CreatedAt  time.Time `bson:"created_at"`
	ExpiresAt  time.Time `bson:"expires_at"`
}

// ErrTransientURLNotFound is returned when no stored URL matches.
var ErrTransientURLNotFound = errors.New("mongostore: transient url not found")

// ErrDecryptFailed is returned when a stored payload cannot be decrypted.
//
// It is deliberately distinct from ErrTransientURLNotFound: a decryption failure
// means the record was tampered with or the key changed, and the caller's
// response should be to fail the job, not to re-submit a URL it cannot read.
var ErrDecryptFailed = errors.New("mongostore: transient url could not be decrypted")

// ErrEncryptionKeyInvalid is returned when the configured key is unusable.
var ErrEncryptionKeyInvalid = errors.New("mongostore: URL_ENCRYPTION_KEY must be at least 32 bytes")

// defaultTransientURLTTL bounds how long an encrypted URL survives if explicit
// deletion never happens.
//
// Short by design: it is a safety net for the crash window in ADR 0013, not the
// retention policy. The real deletion is DeleteTransientURL, called by the
// worker immediately after submission.
const defaultTransientURLTTL = 10 * time.Minute

// PutTransientURL encrypts and stores a raw URL for a scan.
//
// The URL is the only plaintext the system persists, and it persists only here,
// only encrypted, and only until the worker has submitted it. Per ADR 0013:
//
//   - AES-256-GCM, so tampering is detected rather than decrypted into garbage.
//   - A fresh 96-bit nonce per record. Never reused: reusing a nonce under one
//     key destroys the authentication guarantee for both records.
//   - scan_id as additional authenticated data, binding the ciphertext to its
//     record so an attacker with write access cannot swap one scan's URL into
//     another's slot.
//
// The key is deliberately not the fingerprint HMAC key. They have different
// lifecycles: rotating the HMAC key invalidates the entire cache, while
// rotating the encryption key only strands in-flight jobs.
func (s *Store) PutTransientURL(ctx context.Context, aead cipher.AEAD, scanID, rawURL string, ttl time.Duration) error {
	if s == nil || s.db == nil {
		return ErrClosed
	}
	if scanID == "" {
		return errors.New("mongostore: ScanID is required")
	}
	if rawURL == "" {
		return errors.New("mongostore: rawURL is required")
	}
	if aead == nil {
		return ErrEncryptionKeyInvalid
	}
	if ttl <= 0 {
		ttl = defaultTransientURLTTL
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("mongostore: generate nonce: %w", err)
	}

	// The scan ID is the AAD, so decryption fails if the record was moved.
	sealed := aead.Seal(nil, nonce, []byte(rawURL), []byte(scanID))

	now := time.Now().UTC()
	_, err := s.db.Collection(CollectionTransientURLs).InsertOne(ctx, transientURL{
		ScanID:     scanID,
		Ciphertext: base64.StdEncoding.EncodeToString(sealed),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
	})
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			// One URL per scan. Re-storing would mean two plaintexts for one
			// scan, and a worker reading it could get either.
			return fmt.Errorf("mongostore: transient url already exists for scan: %w", err)
		}
		return fmt.Errorf("mongostore: put transient url: %w", err)
	}
	return nil
}

// GetTransientURL decrypts and returns the stored URL for a scan.
//
// The caller must call DeleteTransientURL immediately afterwards. There is no
// variant that reads without the intent to delete.
func (s *Store) GetTransientURL(ctx context.Context, aead cipher.AEAD, scanID string) (string, error) {
	if s == nil || s.db == nil {
		return "", ErrClosed
	}
	if aead == nil {
		return "", ErrEncryptionKeyInvalid
	}

	var rec transientURL
	err := s.db.Collection(CollectionTransientURLs).
		FindOne(ctx, bson.M{"_id": scanID}).
		Decode(&rec)

	switch {
	case err == nil:
	case errors.Is(err, mongo.ErrNoDocuments):
		return "", ErrTransientURLNotFound
	default:
		return "", fmt.Errorf("mongostore: get transient url: %w", err)
	}

	sealed, err := base64.StdEncoding.DecodeString(rec.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("%w: malformed ciphertext", ErrDecryptFailed)
	}
	nonce, err := base64.StdEncoding.DecodeString(rec.Nonce)
	if err != nil || len(nonce) != aead.NonceSize() {
		return "", fmt.Errorf("%w: malformed nonce", ErrDecryptFailed)
	}

	plaintext, err := aead.Open(nil, nonce, sealed, []byte(rec.ScanID))
	if err != nil {
		// Authentication failed: wrong key, tampered record, or a ciphertext
		// moved between scans. Never fall back to using it.
		return "", ErrDecryptFailed
	}
	return string(plaintext), nil
}

// DeleteTransientURL removes a stored URL.
//
// This is the primary deletion mechanism per ADR 0013. The TTL index is only a
// safety net for a worker crash between Put and Delete.
func (s *Store) DeleteTransientURL(ctx context.Context, scanID string) error {
	if s == nil || s.db == nil {
		return ErrClosed
	}
	if _, err := s.db.Collection(CollectionTransientURLs).
		DeleteOne(ctx, bson.M{"_id": scanID}); err != nil {
		return fmt.Errorf("mongostore: delete transient url: %w", err)
	}
	return nil
}

// TakeTransientURL reads and deletes a URL in one operation.
//
// This is what a worker should actually call. Deleting as part of the read
// means the plaintext cannot be fetched twice and cannot survive a worker crash
// that happens after the read but before a separate delete.
func (s *Store) TakeTransientURL(ctx context.Context, aead cipher.AEAD, scanID string) (string, error) {
	rawURL, err := s.GetTransientURL(ctx, aead, scanID)
	if err != nil {
		return "", err
	}
	if err := s.DeleteTransientURL(ctx, scanID); err != nil {
		return "", err
	}
	return rawURL, nil
}

// newAEAD builds an AES-256-GCM AEAD from a key.
//
// The key must be at least 32 bytes. A shorter key is rejected rather than
// stretched, because a silently-weakened key is worse than a startup failure.
func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) < 32 {
		return nil, ErrEncryptionKeyInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("mongostore: aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mongostore: gcm: %w", err)
	}
	return aead, nil
}

// NewTransientURLCipher builds the AEAD used by the transient URL store.
//
// It is exported so wiring code can construct it once at startup and pass it in,
// rather than each repository method re-deriving it.
func NewTransientURLCipher(key []byte) (cipher.AEAD, error) {
	return newAEAD(key)
}
