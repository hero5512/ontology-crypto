package ecies

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"github.com/ontio/ontology-crypto/sm2"
	"github.com/prometheus/common/log"
	"io"
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
	p256 := sm2.SM2P256V1()
	priKey, _ := ecdsa.GenerateKey(p256, rand.Reader)
	pubKey := &priKey.PublicKey
	msg, _ := hex.DecodeString(testcase_Dec.message)
	_, _ = io.ReadFull(rand.Reader, msg[:])
	c, _ := EciesEncrypt(pubKey, msg)

	m, _ := EciesDecrypt(priKey, c)
	if reflect.DeepEqual(msg, m) != true {
		t.Error("ecies enc error!")
	}
	cstring := hex.EncodeToString(c)
	log.Info(hex.EncodeToString(priKey.D.Bytes()))
	log.Info(hex.EncodeToString(priKey.PublicKey.X.Bytes()))
	log.Info(hex.EncodeToString(priKey.PublicKey.Y.Bytes()))
	log.Info(cstring)
}
