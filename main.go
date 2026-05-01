package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/pkg/errors"

	"lab2_digital_signatures/rsapkcs1v15"
)

const (
	exitCodeSuccess = 0
	exitCodeError   = 1
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Printf("%+v", err)
		os.Exit(exitCodeError)
	}

	os.Exit(exitCodeSuccess)
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		printUsage(out)
		return errors.Errorf("missing command")
	}

	switch args[0] {
	case "keygen":
		return runKeygen(args[1:], out)
	case "sign":
		return runSign(args[1:], out)
	case "verify":
		return runVerify(args[1:], out)
	case "-h", "--help", "help":
		printUsage(out)
		return nil
	default:
		printUsage(out)
		return errors.Errorf("unknown command: %s", args[0])
	}
}

func printUsage(out io.Writer) {
	_, _ = fmt.Fprintln(out, "Usage:")
	_, _ = fmt.Fprintf(out, "  go run . keygen -bits %d -priv ./private.json -pub ./public.json\n", rsapkcs1v15.RSAKeyBitsDefault)
	_, _ = fmt.Fprintln(out, "  go run . sign -priv ./private.json -text <TEXT>")
	_, _ = fmt.Fprintln(out, "  go run . verify -pub ./public.json -text <TEXT> -sig <HEX>")
}

func runKeygen(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	bits := fs.Int("bits", rsapkcs1v15.RSAKeyBitsDefault, "RSA modulus size in bits")
	privPath := fs.String("priv", "", "path to write private key (json)")
	pubPath := fs.String("pub", "", "path to write public key (json)")
	if err := fs.Parse(args); err != nil {
		return errors.Wrap(err, "parse flags")
	}

	if *privPath == "" || *pubPath == "" {
		printUsage(out)
		return errors.Errorf("missing -priv or -pub")
	}

	priv, err := rsapkcs1v15.GenerateKey(*bits)
	if err != nil {
		return errors.Wrap(err, "generate key")
	}

	if err := writePrivateKey(*privPath, priv); err != nil {
		return errors.Wrap(err, "write private key")
	}
	if err := writePublicKey(*pubPath, &priv.PublicKey); err != nil {
		return errors.Wrap(err, "write public key")
	}

	_, err = fmt.Fprintf(out, "OK: generated RSA key (%d bits)\n", *bits)
	return errors.Wrap(err, "write output")
}

func runSign(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	privPath := fs.String("priv", "", "path to private key (json)")
	text := fs.String("text", "", "text to sign")
	if err := fs.Parse(args); err != nil {
		return errors.Wrap(err, "parse flags")
	}

	if *privPath == "" || *text == "" {
		printUsage(out)
		return errors.Errorf("missing -priv or -text")
	}

	priv, err := readPrivateKey(*privPath)
	if err != nil {
		return errors.Wrap(err, "read private key")
	}

	sig, err := rsapkcs1v15.SignSHA1(priv, []byte(*text))
	if err != nil {
		return errors.Wrap(err, "sign")
	}

	_, err = fmt.Fprintln(out, hex.EncodeToString(sig))
	return errors.Wrap(err, "write output")
}

func runVerify(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	pubPath := fs.String("pub", "", "path to public key (json)")
	text := fs.String("text", "", "text to verify")
	sigHex := fs.String("sig", "", "signature hex")
	if err := fs.Parse(args); err != nil {
		return errors.Wrap(err, "parse flags")
	}

	if *pubPath == "" || *text == "" || *sigHex == "" {
		printUsage(out)
		return errors.Errorf("missing -pub, -text or -sig")
	}

	pub, err := readPublicKey(*pubPath)
	if err != nil {
		return errors.Wrap(err, "read public key")
	}

	sigHexNorm := strings.TrimSpace(*sigHex)
	sig, err := hex.DecodeString(sigHexNorm)
	if err != nil {
		return errors.Wrap(err, "decode signature hex")
	}

	if err := rsapkcs1v15.VerifySHA1(pub, []byte(*text), sig); err != nil {
		return errors.Wrap(err, "verify")
	}

	_, err = fmt.Fprintln(out, "OK")
	return errors.Wrap(err, "write output")
}
