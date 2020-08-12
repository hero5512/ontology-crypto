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

package primitives

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

const SECURITY_BITS = 64

func CreateCommitmentWithRandom(message *big.Int, blindingFactor *big.Int) (*big.Int, error) {
	if message == nil || blindingFactor == nil {
		err := errors.New("parameter should not be null")
		return nil, err
	}
	h := sha256.New()
	h.Write(message.Bytes())
	h.Write(blindingFactor.Bytes())
	return new(big.Int).SetBytes(h.Sum(nil)), nil
}

func CreateCommitment(message *big.Int) (*big.Int, *big.Int, error) {
	if message == nil {
		err := errors.New("parameter should not be null")
		return nil, nil, err
	}
	blindingFactorBytes, err := generateRandomBytes(SECURITY_BITS)
	if err != nil {
		return nil, nil, err
	}
	blindingFactor := new(big.Int).SetBytes(blindingFactorBytes)
	h := sha256.New()
	h.Write(message.Bytes())
	h.Write(blindingFactor.Bytes())
	return new(big.Int).SetBytes(h.Sum(nil)), blindingFactor, nil
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
