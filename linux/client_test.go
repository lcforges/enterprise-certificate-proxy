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

package linux

import (
	"crypto"
	"testing"
)

var testModule = "/usr/local/lib/softhsm/libsofthsm2.so"
var testSlot = "0x268c8a20"
var testLabel = "Demo Object"
var testUserPin = "0000"

func TestEncrypt(t *testing.T) {
	sk, err := NewSecureKey(testModule, testSlot, testLabel, testUserPin)
	if err != nil {
		t.Errorf("Client Encrypt: error generating secure key, %q", err)
	}
	message := "Plain text to encrypt"
	bMessage := []byte(message)
	//Softhsm only supports SHA1
	res, err := (sk.key).WithHash(crypto.SHA1)
	sk.key = res
	_, err = sk.Encrypt(bMessage)
	if err != nil {
		t.Errorf("Client Encrypt error: %q", err)
	}
}