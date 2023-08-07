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
	"crypto"
	"crypto/sha256"
	"testing"

	"github.com/google/go-pkcs11/pkcs11"
)

var testModule = "/usr/local/lib/softhsm/libsofthsm2.so"
var testSlot = "0x268c8a20"
var testLabel = "Demo Object"
var testUserPin = "0000"

func makeTestKey() (*Key, error) {
	return Cred(testModule, testSlot, testLabel, testUserPin)
}

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
	key, _ := makeTestKey()
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)
	ciphertext, err := key.encryptRSA(sha256.New(), bMsg)
	if err != nil {
		t.Fatalf("EncryptRSA error: %q", err)
	}
	if ciphertext == nil {
		t.Errorf("EncryptRSA error: empty ciphertext")
	}
}

func TestCredLinux(t *testing.T) {
	_, err := makeTestKey()
	if err != nil {
		t.Errorf("Cred error: %q", err)
	}
}

func BenchmarkEncryptRSACrypto(b *testing.B) {
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)
	hashFunc := sha256.New()
	key, errCred := makeTestKey()
	if errCred != nil {
		b.Errorf("Cred error: %q", errCred)
		return
	}
	b.Run("encryptRSA Crypto", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, errEncrypt := key.encryptRSA(hashFunc, bMsg)
			if errEncrypt != nil {
				b.Errorf("EncryptRSA error: %q", errEncrypt)
				return
			}
		}
	})
}

func TestEncryptRSAWithPKCS11(t *testing.T) {
	key, _ := makeTestKey()
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)
	// Softhsm only supports SHA1
	res, err := pkcs11.WithHash(key.privKey, crypto.SHA1)
	key.privKey = res
	_, err = key.encryptRSAWithPKCS11(bMsg)
	if err != nil {
		t.Errorf("EncryptRSAGoPKCS11 error: %q", err)
	}
}

func TestDecryptRSAWithPKCS11(t *testing.T) {
	key, _ := makeTestKey()
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)
	// Softhsm only supports SHA1
	res, err := pkcs11.WithHash(key.privKey, crypto.SHA1)
	key.privKey = res
	if err != nil {
		t.Errorf("WithHash error: %q", err)
	}
	ciphertext, err := key.encryptRSAWithPKCS11(bMsg)
	if err != nil {
		t.Errorf("EncryptRSAGoPKCS11 error: %q", err)
	}
	decrypted, err := key.decryptRSAWithPKCS11(ciphertext)
	if err != nil {
		t.Fatalf("DecryptRSAGoPKCS11 error: %v", err)
	}
	decrypted = bytes.Trim(decrypted, "\x00")
	if string(decrypted) != msg {
		t.Errorf("DecryptRSAGoPKCS11 Error: expected %q, got %q", msg, string(decrypted))
	}
}

func TestEncrypt(t *testing.T) {
	key, _ := makeTestKey()
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)
	// Softhsm only supports SHA1
	res, err := pkcs11.WithHash(key.privKey, crypto.SHA1)
	key.privKey = res
	_, err = key.Encrypt(bMsg)
	if err != nil {
		t.Errorf("Encrypt error: %q", err)
	}
}

func TestDecrypt(t *testing.T) {
	key, _ := makeTestKey()
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)
	// Softhsm only supports SHA1
	res, err := pkcs11.WithHash(key.privKey, crypto.SHA1)
	key.privKey = res
	if err != nil {
		t.Errorf("WithHash error: %q", err)
	}
	ciphertext, err := key.Encrypt(bMsg)
	if err != nil {
		t.Errorf("Encrypt error: %q", err)
	}
	decrypted, err := key.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	decrypted = bytes.Trim(decrypted, "\x00")
	if string(decrypted) != msg {
		t.Errorf("Decrypt error: expected %q, got %q", msg, string(decrypted))
	}
}
