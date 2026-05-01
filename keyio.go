package main

import (
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/pkg/errors"

	"lab2_digital_signatures/rsapkcs1v15"
)

type publicKeyJSON struct {
	N string `json:"n"`
	E int    `json:"e"`
}

type privateKeyJSON struct {
	N string `json:"n"`
	E int    `json:"e"`
	D string `json:"d"`
	P string `json:"p,omitempty"`
	Q string `json:"q,omitempty"`
}

func writePublicKey(path string, pub *rsapkcs1v15.PublicKey) error {
	if pub == nil || pub.N == nil || pub.E <= 0 {
		return errors.Wrap(rsapkcs1v15.ErrInvalidKey, "public key is empty")
	}

	payload := publicKeyJSON{
		N: hex.EncodeToString(pub.N.Bytes()),
		E: pub.E,
	}

	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return errors.Wrap(err, "marshal public key")
	}

	return errors.Wrap(os.WriteFile(path, append(b, '\n'), filePermOwnerReadWrite), "write public key")
}

func writePrivateKey(path string, priv *rsapkcs1v15.PrivateKey) error {
	if priv == nil || priv.N == nil || priv.D == nil || priv.E <= 0 {
		return errors.Wrap(rsapkcs1v15.ErrInvalidKey, "private key is empty")
	}

	payload := privateKeyJSON{
		N: hex.EncodeToString(priv.N.Bytes()),
		E: priv.E,
		D: hex.EncodeToString(priv.D.Bytes()),
	}
	if priv.P != nil {
		payload.P = hex.EncodeToString(priv.P.Bytes())
	}
	if priv.Q != nil {
		payload.Q = hex.EncodeToString(priv.Q.Bytes())
	}

	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return errors.Wrap(err, "marshal private key")
	}

	return errors.Wrap(os.WriteFile(path, append(b, '\n'), filePermOwnerReadWrite), "write private key")
}

func readPublicKey(path string) (*rsapkcs1v15.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "read public key")
	}

	var payload publicKeyJSON
	if err := json.Unmarshal(b, &payload); err != nil {
		return nil, errors.Wrap(err, "unmarshal public key")
	}

	nBytes, err := hex.DecodeString(payload.N)
	if err != nil {
		return nil, errors.Wrap(err, "decode public key n")
	}

	pub := &rsapkcs1v15.PublicKey{
		N: bytesToBigInt(nBytes),
		E: payload.E,
	}
	if pub.N.Sign() <= 0 || pub.E <= 0 {
		return nil, errors.Wrap(rsapkcs1v15.ErrInvalidKey, "public key fields invalid")
	}

	return pub, nil
}

func readPrivateKey(path string) (*rsapkcs1v15.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "read private key")
	}

	var payload privateKeyJSON
	if err := json.Unmarshal(b, &payload); err != nil {
		return nil, errors.Wrap(err, "unmarshal private key")
	}

	nBytes, err := hex.DecodeString(payload.N)
	if err != nil {
		return nil, errors.Wrap(err, "decode private key n")
	}

	dBytes, err := hex.DecodeString(payload.D)
	if err != nil {
		return nil, errors.Wrap(err, "decode private key d")
	}

	priv := &rsapkcs1v15.PrivateKey{
		PublicKey: rsapkcs1v15.PublicKey{
			N: bytesToBigInt(nBytes),
			E: payload.E,
		},
		D: bytesToBigInt(dBytes),
	}
	if priv.N.Sign() <= 0 || priv.E <= 0 || priv.D.Sign() <= 0 {
		return nil, errors.Wrap(rsapkcs1v15.ErrInvalidKey, "private key fields invalid")
	}

	return priv, nil
}
