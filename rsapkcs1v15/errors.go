package rsapkcs1v15

import stderrs "errors"

var (
	// ErrInvalidKey indicates that the provided key material is invalid.
	ErrInvalidKey = stderrs.New("invalid key")

	// ErrInvalidSignature indicates that a signature is malformed or does not verify.
	ErrInvalidSignature = stderrs.New("invalid signature")
)
