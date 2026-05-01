package rsapkcs1v15

import (
	"testing"

	"github.com/pkg/errors"
)

func TestSignVerify_RoundTrip(t *testing.T) {
	priv, err := GenerateKey(RSAKeyBitsMin)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	message := []byte("hello signatures")
	sig, err := SignSHA1(priv, message)
	if err != nil {
		t.Fatalf("SignSHA1() error: %v", err)
	}

	if err := VerifySHA1(&priv.PublicKey, message, sig); err != nil {
		t.Fatalf("VerifySHA1() error: %v", err)
	}

	badMessage := []byte("hello signatures!")
	if err := VerifySHA1(&priv.PublicKey, badMessage, sig); err == nil {
		t.Fatalf("VerifySHA1() expected error for modified message")
	}
}

func TestVerify_InvalidLength(t *testing.T) {
	priv, err := GenerateKey(RSAKeyBitsMin)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	err = VerifySHA1(&priv.PublicKey, []byte("a"), []byte{1, 2, 3})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}
