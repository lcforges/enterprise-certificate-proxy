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
	"crypto/rand"
	"crypto/sha256"
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
	// parameters from internal/signer/util certificate_config.json
	key, err := Cred("pkcs11_module.so","0x1739427","gecc","0000")
	if err != nil {
		t.Errorf("EncryptRSA Cred error %v", err)
	}
	_, err = key.EncryptRSA(sha256.New(), rand.Reader, nil,nil)
	if err != nil {
		t.Errorf("EncryptRSA error %v", err)
	}
}