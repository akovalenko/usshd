package main

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestLoadHostKeysBootstrap pins the first-start bootstrap: an empty working
// directory grows the three canonical key files (0600, atomically — no temp
// leftovers), and a second call loads the same identities instead of
// regenerating.
func TestLoadHostKeysBootstrap(t *testing.T) {
	t.Chdir(t.TempDir())

	signers, err := loadHostKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != len(hostKeySpecs) {
		t.Fatalf("%d signers, want %d", len(signers), len(hostKeySpecs))
	}

	types := map[string]bool{}
	fprints := make([]string, len(signers))
	for i, s := range signers {
		types[s.PublicKey().Type()] = true
		fprints[i] = ssh.FingerprintSHA256(s.PublicKey())
	}
	for _, want := range []string{"ecdsa-sha2-nistp256", "ssh-rsa", "ssh-ed25519"} {
		if !types[want] {
			t.Errorf("missing key type %s", want)
		}
	}

	for _, spec := range hostKeySpecs {
		fi, err := os.Stat(spec.file)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0600 {
			t.Errorf("%s: mode %o, want 0600", spec.file, perm)
		}
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(hostKeySpecs) {
		t.Errorf("%d directory entries, want %d (temp leftovers?)",
			len(entries), len(hostKeySpecs))
	}

	again, err := loadHostKeys()
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range again {
		if got := ssh.FingerprintSHA256(s.PublicKey()); got != fprints[i] {
			t.Errorf("%s regenerated on second load: %s != %s",
				hostKeySpecs[i].file, got, fprints[i])
		}
	}
}

// TestLoadHostKeysRejectsCorrupt pins that an existing-but-unparseable key
// file is an error and is left untouched — never silently regenerated, which
// would rotate the server's identity behind the deployer's back.
func TestLoadHostKeysRejectsCorrupt(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("id_ecdsa", []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := loadHostKeys()
	if err == nil {
		t.Fatal("corrupt id_ecdsa accepted")
	}
	if !strings.Contains(err.Error(), "id_ecdsa") {
		t.Errorf("error does not name the file: %v", err)
	}
	data, err := os.ReadFile("id_ecdsa")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "not a key" {
		t.Error("corrupt file was overwritten")
	}
}
