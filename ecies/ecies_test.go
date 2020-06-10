package ecies

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"testing"
)

type EciesData struct {
	pubkey_x string
	pubkey_y string
	privkey  string
	message  string
	cipher   string
}

var testcase_Dec = EciesData{
	message:  "ce8f1ce36e5e62b16772",
}

func TestEcies(t *testing.T) {
	p256 := elliptic.P256()
	priKey, _ := ecdsa.GenerateKey(p256, rand.Reader)
	pubKey := &priKey.PublicKey
	msg, _ := hex.DecodeString(testcase_Dec.message)
	c, _ := EciesEncrypt(pubKey, msg)

	m, _ := EciesDecrypt(priKey, c)
	if reflect.DeepEqual(msg, m) != true {
		t.Error("ecies enc error!")
	}
}
