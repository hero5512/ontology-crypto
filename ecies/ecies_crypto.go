package ecies

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
)

var ErrParams = fmt.Errorf("ecies: illegal params")

func EciesEncrypt(pub *ecdsa.PublicKey, data []byte) ([]byte, error) {
	if len(data) <= 0 {
		return nil, ErrParams
	}
	publicKeyEcies := ImportECDSAPublic(pub)
	encryptDataByte, err := Encrypt(rand.Reader, publicKeyEcies, data, nil, nil)
	if err != nil {
		return nil, err
	}
	return encryptDataByte, nil
}

func EciesDecrypt(priv *ecdsa.PrivateKey, encryptData []byte) ([]byte, error) {
	privateKeyEcies := ImportECDSA(priv)
	decryptDataByte, err := privateKeyEcies.Decrypt(encryptData, nil, nil)
	if err != nil {
		return nil, err
	}
	return decryptDataByte, nil
}
