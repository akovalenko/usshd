package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// hostKeySpecs names the daemon's host key files and how to generate each type
// when its file is absent. The filenames in the working directory are the
// installation convention earlier deployments followed with ssh-keygen.
var hostKeySpecs = []struct {
	file string
	gen  func() (crypto.PrivateKey, error)
}{
	{"id_ecdsa", func() (crypto.PrivateKey, error) {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}},
	{"id_rsa", func() (crypto.PrivateKey, error) {
		return rsa.GenerateKey(rand.Reader, 3072)
	}},
	{"id_ed25519", func() (crypto.PrivateKey, error) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	}},
}

// loadHostKeys returns one signer per host key file, generating any missing
// file on the spot — the same first-start bootstrap philosophy as the database
// (see openDB): an empty directory becomes a working installation. An existing
// but unparseable file is an error, never regenerated: host keys are the
// server's identity, and replacing them behind the deployer's back would turn
// every client's known_hosts entry into a mismatch warning.
func loadHostKeys() ([]ssh.Signer, error) {
	var signers []ssh.Signer
	for _, spec := range hostKeySpecs {
		signer, err := loadOrCreateHostKey(spec.file, spec.gen)
		if err != nil {
			return nil, fmt.Errorf("host key %s: %w", spec.file, err)
		}
		signers = append(signers, signer)
	}
	return signers, nil
}

func loadOrCreateHostKey(file string,
	gen func() (crypto.PrivateKey, error)) (ssh.Signer, error) {

	data, err := os.ReadFile(file)
	created := false
	if errors.Is(err, fs.ErrNotExist) {
		data, err = createHostKey(file, gen)
		created = true
	}
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		if created {
			return nil, err
		}
		return nil, fmt.Errorf(
			"exists but does not parse (%v); refusing to regenerate — "+
				"remove the file to give the server a new identity", err)
	}
	if created {
		log.Printf("host key %s not found — GENERATED a fresh %s key (%s); "+
			"if this installation had keys before, they were not found in %s",
			file, signer.PublicKey().Type(),
			ssh.FingerprintSHA256(signer.PublicKey()), mustGetwd())
	}
	return signer, nil
}

// createHostKey generates a fresh key and writes it atomically (temp+rename,
// 0600): a crash mid-write must not leave a truncated file that fails to parse
// on the next start. It returns the PEM bytes it wrote, so the caller parses
// exactly what future starts will read.
func createHostKey(file string,
	gen func() (crypto.PrivateKey, error)) ([]byte, error) {

	key, err := gen()
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(block)

	tmp, err := os.CreateTemp(filepath.Dir(file), filepath.Base(file)+".tmp*")
	if err != nil {
		return nil, err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return nil, err
	}
	if err := os.Rename(tmp.Name(), file); err != nil {
		os.Remove(tmp.Name())
		return nil, err
	}
	return data, nil
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		return "the working directory"
	}
	return wd
}
