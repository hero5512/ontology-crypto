package util

import (
	"bytes"
	"math/big"
	"reflect"
)

func BytesCombine(pBytes ...[]byte) []byte {
	var buffer bytes.Buffer

	for i := 0; i < len(pBytes); i++ {
		buffer.Write(pBytes[i])
	}

	return buffer.Bytes()
}


func BytesCompare(bytesA, bytesB []byte) bool {
	if reflect.DeepEqual(bytesA, bytesB) {
		return true
	}
	return false
}

func IntToByte(i *big.Int) []byte {
	b1, b2 := [32]byte{}, i.Bytes()
	copy(b1[32-len(b2):], b2)
	return b1[:]
}