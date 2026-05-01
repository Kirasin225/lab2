package main

import (
	"bytes"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"lab2_digital_signatures/rsapkcs1v15"
)

func TestCLI_KeygenSignVerify(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.json")
	pubPath := filepath.Join(dir, "pub.json")

	{
		var out bytes.Buffer
		if err := run([]string{"keygen", "-bits", strconv.Itoa(rsapkcs1v15.RSAKeyBitsMin), "-priv", privPath, "-pub", pubPath}, &out); err != nil {
			t.Fatalf("keygen error: %v", err)
		}
	}

	var sigHex string
	{
		var out bytes.Buffer
		if err := run([]string{"sign", "-priv", privPath, "-text", "hello"}, &out); err != nil {
			t.Fatalf("sign error: %v", err)
		}
		sigHex = strings.TrimSpace(out.String())
		if sigHex == "" {
			t.Fatalf("empty signature")
		}
	}

	{
		var out bytes.Buffer
		if err := run([]string{"verify", "-pub", pubPath, "-text", "hello", "-sig", sigHex}, &out); err != nil {
			t.Fatalf("verify error: %v", err)
		}
		if strings.TrimSpace(out.String()) != "OK" {
			t.Fatalf("verify output = %q, want OK", strings.TrimSpace(out.String()))
		}
	}

	{
		var out bytes.Buffer
		if err := run([]string{"verify", "-pub", pubPath, "-text", "hello!", "-sig", sigHex}, &out); err == nil {
			t.Fatalf("expected verify error for modified text")
		}
	}
}

func TestCLI_Verify_InvalidSigHex(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "priv.json")
	pubPath := filepath.Join(dir, "pub.json")

	{
		var out bytes.Buffer
		if err := run([]string{"keygen", "-bits", strconv.Itoa(rsapkcs1v15.RSAKeyBitsMin), "-priv", privPath, "-pub", pubPath}, &out); err != nil {
			t.Fatalf("keygen error: %v", err)
		}
	}

	{
		var out bytes.Buffer
		if err := run([]string{"verify", "-pub", pubPath, "-text", "hello", "-sig", "zz"}, &out); err == nil {
			t.Fatalf("expected error")
		}
	}
}
