/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

// aggregated Schnorr {n,n}-Signatures
//See https://eprint.iacr.org/2018/068.pdf, https://eprint.iacr.org/2018/483.pdf subsection 5.1
package agg_sign

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/primitives"
	"math/big"
)

var (
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
)

type KeyAgg struct {
	APK  *ecdsa.PublicKey
	Hash *big.Int
}

func KeyAggregation(myPk *ecdsa.PublicKey, otherPk *ecdsa.PublicKey) (*KeyAgg, error) {
	if myPk == nil || otherPk == nil {
		err := errors.New("publicKey should not be null")
		return nil, err
	}
	// TODO check curve
	curve := myPk.Curve
	myCompressedPk := new(big.Int).SetBytes(ec.EncodePublicKey(myPk, true))
	otherCompressedPk := new(big.Int).SetBytes(ec.EncodePublicKey(otherPk, true))

	hash := CreateHash([]*big.Int{big1, myCompressedPk, myCompressedPk, otherCompressedPk})
	a1X, a1Y := curve.ScalarMult(myPk.X, myPk.Y, hash.Bytes())

	hash2 := CreateHash([]*big.Int{big1, otherCompressedPk, myCompressedPk, otherCompressedPk})
	a2X, a2Y := curve.ScalarMult(otherPk.X, otherPk.Y, hash2.Bytes())

	apkX, apkY := curve.Add(a1X, a1Y, a2X, a2Y)

	apk := &ecdsa.PublicKey{
		Curve: curve,
		X:     apkX,
		Y:     apkY,
	}
	keyAgg := &KeyAgg{
		APK:  apk,
		Hash: hash,
	}
	return keyAgg, nil
}

func KeyAggregationN(pks []*ecdsa.PublicKey, partyIndex int) (*KeyAgg, error) {
	if pks == nil || len(pks) == 0 || partyIndex <= 0 {
		err := errors.New("illegal parameter")
		return nil, err
	}
	if partyIndex >= len(pks) {
		err := errors.New("pks's length should more than partyIndex")
		return nil, err
	}
	// TODO check curve
	curve := pks[partyIndex].Curve

	compressPks := make([]*big.Int, len(pks))
	for i, pk := range pks {
		compressPks[i] = new(big.Int).SetBytes(ec.EncodePublicKey(pk, true))
	}

	hashes := make([]*big.Int, len(pks))
	for i, x := range compressPks {
		param := make([]*big.Int, len(pks)+2)
		param[0] = big1
		param[1] = x
		for j, y := range compressPks {
			param[j+2] = y
		}
		hashes[i] = CreateHash(param)
	}

	x := big.NewInt(0)
	y := big.NewInt(0)

	for i := 0; i < len(pks); i++ {
		hash := hashes[i]
		tmp1, tmp2 := curve.ScalarMult(pks[i].X, pks[i].Y, hash.Bytes())
		x, y = curve.Add(x, y, tmp1, tmp2)
	}

	apk := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	keyAgg := &KeyAgg{
		APK:  apk,
		Hash: hashes[partyIndex],
	}
	return keyAgg, nil
}

type EphemeralKey struct {
	KeyPair     *ec.PrivateKey
	Commitment  *big.Int
	BlindFactor *big.Int
}

func Create() (*EphemeralKey, error) {
	privateKey, publicKey, err := keypair.GenerateKeyPair(keypair.PK_AGGSIGN, keypair.SECP256K1)
	if err != nil {
		return nil, err
	}
	compressPubKey := ec.EncodePublicKey(publicKey.(*ec.PublicKey).PublicKey, true)
	commitment, blindFactor, err := primitives.CreateCommitment(new(big.Int).SetBytes(compressPubKey))
	if err != nil {
		return nil, err
	}
	key := &EphemeralKey{
		KeyPair:     privateKey.(*ec.PrivateKey),
		Commitment:  commitment,
		BlindFactor: blindFactor,
	}
	return key, nil
}

func CreateFromPrivateKey(x1 ec.PrivateKey, message []byte) (*EphemeralKey, error) {
	curve := x1.Curve
	hashPrivateKeyMessage := CreateHash([]*big.Int{x1.D, new(big.Int).SetBytes(message)})

	X, Y := curve.ScalarBaseMult(hashPrivateKeyMessage.Bytes())

	publicKey := ecdsa.PublicKey{
		Curve: curve,
		X:     X,
		Y:     Y,
	}

	ephemeralPrivateKey := ec.PrivateKey{
		Algorithm: ec.AGGSIGN,
		PrivateKey: &ecdsa.PrivateKey{
			PublicKey: publicKey,
			D:         hashPrivateKeyMessage,
		},
	}

	compressPubKey := ec.EncodePublicKey(&publicKey, true)
	commitment, blindFactor, err := primitives.CreateCommitment(new(big.Int).SetBytes(compressPubKey))
	if err != nil {
		return nil, err
	}
	ephemeralKey := &EphemeralKey{
		KeyPair:     &ephemeralPrivateKey,
		Commitment:  commitment,
		BlindFactor: blindFactor,
	}
	return ephemeralKey, nil
}

func TestCom(pubKey *ecdsa.PublicKey, blindFactor *big.Int, comm *big.Int) (bool, error) {
	if pubKey == nil || blindFactor == nil || comm == nil {
		err := errors.New("illegal parameter")
		return false, err
	}
	compressPubKey := ec.EncodePublicKey(pubKey, true)
	computedComm, err := primitives.CreateCommitmentWithRandom(new(big.Int).SetBytes(compressPubKey), blindFactor)
	if err != nil {
		return false, err
	}
	return computedComm.Cmp(comm) == 0, nil
}

func AddEphemeralPubKeys(pubKey1 *ecdsa.PublicKey, pubKey2 *ecdsa.PublicKey) *ecdsa.PublicKey {
	if pubKey1 == nil || pubKey2 == nil {
		return nil
	}
	// TODO check pubKey1 and pubKey2's curve
	curve := pubKey1.Curve
	ephemeralX, ephemeralY := curve.Add(pubKey1.X, pubKey1.Y, pubKey2.X, pubKey2.Y)
	pubKeyRes := &ecdsa.PublicKey{
		Curve: pubKey1.Curve,
		X:     ephemeralX,
		Y:     ephemeralY,
	}
	return pubKeyRes
}

func Hash0(rHat *ecdsa.PublicKey, apk *ecdsa.PublicKey, message []byte, muSigBit bool) (*big.Int, error) {
	if rHat == nil || apk == nil {
		err := errors.New("illegal parameter")
		return nil, err
	}
	compressApk := new(big.Int).SetBytes(ec.EncodePublicKey(apk, true))
	bigMessage := new(big.Int).SetBytes(message)
	if muSigBit {
		return CreateHash([]*big.Int{big0, rHat.X, compressApk, bigMessage}), nil
	}
	return CreateHash([]*big.Int{rHat.X, compressApk, bigMessage}), nil
}

func Sign(r *EphemeralKey, c *big.Int, x ecdsa.PrivateKey, a *big.Int) *big.Int {
	s := new(big.Int)
	curve := x.Curve.Params()
	s = s.Mul(c, x.D)
	s = s.Mod(s, curve.N)

	s = s.Mul(s, a)
	s = s.Mod(s, curve.N)
	s = s.Add(s, r.KeyPair.D)
	s = s.Mod(s, curve.N)
	return s
}

func AddSignatureParts(s1 *big.Int, s2 *big.Int, rTag *ecdsa.PublicKey) (*big.Int, *big.Int) {
	if big0.Cmp(s2) == 0 {
		return rTag.X, s1
	}
	curve := rTag.Params()
	s1PlusS2 := new(big.Int)
	s1PlusS2 = s1PlusS2.Add(s1, s2)
	s1PlusS2 = s1PlusS2.Mod(s1PlusS2, curve.N)
	return rTag.X, s1PlusS2
}

func Verify(signature *big.Int, rX *big.Int, apk *ecdsa.PublicKey, message []byte, musign bool) bool {
	if signature == nil || rX == nil || apk == nil {
		return false
	}
	c := new(big.Int)
	curve := apk.Curve
	if musign {
		compressedApk := new(big.Int).SetBytes(ec.EncodePublicKey(apk, true))
		c = CreateHash([]*big.Int{big0, rX, compressedApk, new(big.Int).SetBytes(message)})
	} else {
		compressedApk := new(big.Int).SetBytes(ec.EncodePublicKey(apk, true))
		c = CreateHash([]*big.Int{rX, compressedApk, new(big.Int).SetBytes(message)})
	}

	sGX, sGY := curve.ScalarBaseMult(signature.Bytes())

	cYX, cYY := curve.ScalarMult(apk.X, apk.Y, c.Bytes())

	sGY = sGY.Sub(curve.Params().P, sGY)
	sGX, sGY = curve.Add(sGX, sGY, cYX, cYY)
	sG := &ecdsa.PublicKey{
		Curve: curve,
		X:     sGX,
		Y:     sGY,
	}
	return sG.X.Cmp(rX) == 0
}

func VerifyPartial(signature *big.Int, rX *big.Int, c *big.Int, a *big.Int, publicKey *ecdsa.PublicKey) bool {
	if signature == nil || rX == nil || c == nil || a == nil || publicKey == nil {
		return false
	}
	curve := publicKey.Curve
	sGX, sGY := curve.ScalarBaseMult(signature.Bytes())
	cYX, cYY := curve.ScalarMult(publicKey.X, publicKey.Y, a.Bytes())
	cYX, cYY = curve.ScalarMult(cYX, cYY, c.Bytes())

	sGY = sGY.Sub(curve.Params().P, sGY)
	sGX, sGY = curve.Add(sGX, sGY, cYX, cYY)

	sG := &ecdsa.PublicKey{
		Curve: curve,
		X:     sGX,
		Y:     sGY,
	}
	return sG.X.Cmp(rX) == 0
}

func CreateHash(bigInts []*big.Int) *big.Int {
	h := sha256.New()
	for _, e := range bigInts {
		h.Write(e.Bytes())
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}
