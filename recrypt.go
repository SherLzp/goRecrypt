package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"golang.org/x/crypto/sha3"
	"math/big"
)

var CURVE = elliptic.P256()

func HashToCurve(hash []byte, curve elliptic.Curve) *big.Int {
	hashInt := new(big.Int).SetBytes(hash)
	one := new(big.Int).SetUint64(1)
	N := curve.Params().N
	n := new(big.Int).Sub(N, one)
	result := new(big.Int).Mod(hashInt, n)
	result.Add(result, one)
	return result
}

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

func PublicKeyToBytes(publicKey *ecdsa.PublicKey) []byte {
	result := elliptic.Marshal(CURVE, publicKey.X, publicKey.Y)
	return result
}

func BigIntAdd(a *big.Int, b *big.Int) *big.Int {
	return new(big.Int).Add(a, b)
}

func BigIntMul(a, b *big.Int) *big.Int {
	return new(big.Int).Mul(a, b)
}

func Sha3Hash(message []byte) []byte {
	sha := sha3.New256()
	sha.Write(message)
	return sha.Sum(nil)
}

func GetCurvePoint(pubKey *ecdsa.PublicKey, value []byte) *ecdsa.PublicKey {
	x, y := CURVE.ScalarMult(pubKey.X, pubKey.Y, value)
	return &ecdsa.PublicKey{CURVE, x, y}
}

func Encrypt(message string, pubKey *ecdsa.PublicKey) (cipherText []byte, pubE *ecdsa.PublicKey, pubV *ecdsa.PublicKey, s *big.Int) {
	s = new(big.Int)
	priE, pubE := GenerateKeys()
	priV, pubV := GenerateKeys()
	h := HashToCurve(ConcatBytes(PublicKeyToBytes(pubE), PublicKeyToBytes(pubV)), CURVE)
	s.Add(priV.D, s.Mul(priE.D, h))
	key := Sha3Hash(PublicKeyToBytes(GetCurvePoint(pubKey, BigIntAdd(priE.D, priV.D).Bytes())))
	cipherText = AesCbcEncrypt([]byte(message), key[16:])
	return
}

func ReKeyGen(aPriKey *ecdsa.PrivateKey, bPubKey *ecdsa.PublicKey) (*big.Int, *ecdsa.PublicKey) {
	priX, pubX := GenerateKeys()
	d := HashToCurve(
		ConcatBytes(
			ConcatBytes(
				PublicKeyToBytes(pubX),
				PublicKeyToBytes(bPubKey)),
			PublicKeyToBytes(GetCurvePoint(bPubKey, priX.D.Bytes()))),
		CURVE)
	d.ModInverse(d, CURVE.Params().N)
	rk := BigIntMul(aPriKey.D, d)
	return rk, pubX
}
