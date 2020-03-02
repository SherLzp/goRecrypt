package utils

import (
	"bytes"
	"goRecrypt/curve"
	"golang.org/x/crypto/sha3"
	"math/big"
)

// concat bytes
func ConcatBytes(a, b []byte) []byte {
	var buf bytes.Buffer
	buf.Write(a)
	buf.Write(b)
	return buf.Bytes()
}

// convert message to hash value
func Sha3Hash(message []byte) ([]byte, error) {
	sha := sha3.New256()
	_, err := sha.Write(message)
	if err != nil {
		return nil, err
	}
	return sha.Sum(nil), nil
}

// map hash value to curve
func HashToCurve(hash []byte) (*big.Int) {
	hashInt := new(big.Int).SetBytes(hash)
	return hashInt.Mod(hashInt, curve.N)
}
