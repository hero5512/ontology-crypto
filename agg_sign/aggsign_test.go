package agg_sign

import (
	"crypto/ecdsa"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"testing"
)

func TestSign(t *testing.T) {
	isMuSig := true
	message := []byte{79, 77, 69, 82}
	party1PrivateKey, party1PublicKey, err := keypair.GenerateKeyPair(keypair.PK_AGGSIGN, keypair.SECP256K1)
	if err != nil {
		t.Error(err)
	}
	party2PrivateKey, party2PublicKey, err := keypair.GenerateKeyPair(keypair.PK_AGGSIGN, keypair.SECP256K1)
	if err != nil {
		t.Error(err)
	}
	party1EphemeralKey, err := Create()
	if err != nil {
		t.Error(err)
	}
	party2EphemeralKey, err := Create()
	if err != nil {
		t.Error(err)
	}
	flag, err := TestCom(&party2EphemeralKey.KeyPair.PublicKey, party2EphemeralKey.BlindFactor, party2EphemeralKey.Commitment)
	if err != nil {
		t.Error(err)
	}
	if !flag {
		t.Error("party2EphemeralKey test fail")
	}

	flag, err = TestCom(&party1EphemeralKey.KeyPair.PublicKey, party1EphemeralKey.BlindFactor, party1EphemeralKey.Commitment)
	if err != nil {
		t.Error(err)
	}
	if !flag {
		t.Error("party1EphemeralKey test fail")
	}

	pks := make([]*ecdsa.PublicKey, 2)
	pks[0] = party1PublicKey.(*ec.PublicKey).PublicKey
	pks[1] = party2PublicKey.(*ec.PublicKey).PublicKey
	keyAgg1, err := KeyAggregationN(pks, 0)
	if err != nil {
		t.Error(err)
	}
	keyAgg2, err := KeyAggregationN(pks, 1)
	if err != nil {
		t.Error(err)
	}
	if keyAgg1.APK.X.Cmp(keyAgg2.APK.X) != 0 {
		t.Error("agg1 not equal to agg2")
	}

	party1RTag := AddEphemeralPubKeys(party1EphemeralKey.KeyPair.Public().(*ec.PublicKey).PublicKey, party2EphemeralKey.KeyPair.Public().(*ec.PublicKey).PublicKey)
	party2RTag := AddEphemeralPubKeys(party1EphemeralKey.KeyPair.Public().(*ec.PublicKey).PublicKey, party2EphemeralKey.KeyPair.Public().(*ec.PublicKey).PublicKey)

	if !(party1RTag.X.Cmp(party2RTag.X) == 0) {
		t.Error("parth1RTag not equal to party2RTag")
	}

	party1H0 := Hash0(party1RTag, keyAgg1.APK, message, isMuSig)
	party2H0 := Hash0(party2RTag, keyAgg2.APK, message, isMuSig)

	if !(party1H0.Cmp(party2H0) == 0) {
		t.Error("party1H0 not equal to party2H0")
	}

	sign1 := Sign(party1EphemeralKey, party1H0, *party1PrivateKey.(*ec.PrivateKey).PrivateKey, keyAgg1.Hash)
	sign2 := Sign(party2EphemeralKey, party2H0, *party2PrivateKey.(*ec.PrivateKey).PrivateKey, keyAgg2.Hash)

	if !VerifyPartial(sign1, party1EphemeralKey.KeyPair.X, party1H0, keyAgg1.Hash, party1PublicKey.(*ec.PublicKey).PublicKey) {
		t.Error("verify partial fail")
	}

	r, s := AddSignatureParts(sign1, sign2, party1RTag)

	if !Verify(s, r, keyAgg1.APK, message, isMuSig) {
		t.Error("verify signature fail")
	}
}

func BenchmarkCreate(b *testing.B) {

}

func BenchmarkSign(b *testing.B) {

}

func BenchmarkAddEphemeralPubKeys(b *testing.B) {

}

