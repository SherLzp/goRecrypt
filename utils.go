package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"golang.org/x/crypto/sha3"
	"math/big"
)

func ConcatBytes(a, b []byte) []byte {
	var buf bytes.Buffer
	buf.Write(a)
	buf.Write(b)
	return buf.Bytes()
}

func GenerateKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return privateKey, &privateKey.PublicKey
}

func Sha3Hash(message []byte) []byte {
	sha := sha3.New256()
	sha.Write(message)
	return sha.Sum(nil)
}

func HashToCurve(hash []byte) *big.Int {
	hashInt := new(big.Int).SetBytes(hash)
	//one := new(big.Int).SetUint64(1)
	//res := BigIntSub(N, one)
	//res.Mod(hashInt, res)
	//res.Add(res, one)
	return hashInt.Mod(hashInt, N)
}
