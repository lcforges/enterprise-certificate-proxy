// Copyright 2023 Google LLC.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pkcs11

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha1"
	"testing"
)

func TestParseHexString(t *testing.T) {
	got, err := ParseHexString("0x1739427")
	if err != nil {
		t.Fatalf("ParseHexString error: %v", err)
	}
	want := uint32(0x1739427)
	if got != want {
		t.Errorf("Expected result is %v, got: %v", want, got)
	}
}

func TestParseHexStringFailure(t *testing.T) {
	_, err := ParseHexString("abcdefgh")
	if err == nil {
		t.Error("Expected error but got nil")
	}
}

func TestEncryptRSA(t *testing.T) {
	// Cred parameters from https://paste.googleplex.com/5330692178182144 (slot from line 46)
	key, _ := Cred("/usr/local/lib/softhsm/libsofthsm2.so","0x268c8a20","Demo Object","0000")
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)
	ciphertext, err := key.EncryptRSA(sha256.New(), bMsg)
	if err != nil {
		t.Fatalf("EncryptRSA error: %q", err)
	}
	if ciphertext == nil {
		t.Errorf("EncryptRSA error: empty ciphertext")
	}
}

func TestCredLinux(t *testing.T) {
	// parameters from https://paste.googleplex.com/5330692178182144 (slot from line 46)
	_, err := Cred("/usr/local/lib/softhsm/libsofthsm2.so","0x268c8a20","Demo Object","0000")
	if err != nil {
		t.Errorf("Cred error: %q", err)
	}
}

func BenchmarkEncryptRSACrypto(b *testing.B) {
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)
	hashFunc := sha256.New()
	key, errCred := Cred("/usr/local/lib/softhsm/libsofthsm2.so","0x268c8a20","Demo Object","0000")
	if errCred != nil {
		b.Errorf("Cred error: %q", errCred)
		return
	}
	b.Run("encryptRSA Crypto", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, errEncrypt := key.EncryptRSA(hashFunc, bMsg)
			if errEncrypt != nil {
				b.Errorf("EncryptRSA error: %q", errEncrypt)
				return
			}
		}
	}) 
}

func TestEncryptRSAGoPKCS11(t *testing.T) {
	key, _ := Cred("/usr/local/lib/softhsm/libsofthsm2.so","0x268c8a20","Demo Object","0000")
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)
	ciphertext, err := key.EncryptRSAGoPKCS11(bMsg)
	if err != nil {
		t.Fatalf("EncryptRSAGoPKCS11 error: %q", err)
	}
	if ciphertext == nil {
		t.Errorf("EncryptRSAGoPKCS11 error: empty ciphertext")
	}
}

func TestDecryptRSAGoPKCS11(t *testing.T) {
	key, _ := Cred("/usr/local/lib/softhsm/libsofthsm2.so","0x268c8a20","Demo Object","0000")
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)

	// Softhsm only supports SHA1
	ciphertext, err := key.EncryptRSA(sha1.New(), bMsg)
	if err != nil {
		t.Fatalf("EncryptRSA error: %q", err)
	}
	if ciphertext == nil {
		t.Errorf("EncryptRSA error: empty ciphertext")
	}
	decrypted, err := key.DecryptRSAGoPKCS11(ciphertext)
	if err != nil {
		t.Fatalf("DecryptRSAGoPKCS11 error: %v", err)
	}
	decrypted = bytes.Trim(decrypted,"\x00")
	if string(decrypted) != msg {
		t.Errorf("EncryptRSAGoPKCS11 Error: expected %q, got %q", msg, string(decrypted))
	}
}