package utils

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
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

// convert private key to string
func PrivateKeyToString(privateKey *ecdsa.PrivateKey) string {
	return hex.EncodeToString(privateKey.D.Bytes())
}

// convert string to private key
func PrivateKeyStrToKey(privateKeyStr string) (*ecdsa.PrivateKey, error) {
	priKeyAsBytes, err := hex.DecodeString(privateKeyStr)
	if err != nil {
		return nil, err
	}
	d := new(big.Int).SetBytes(priKeyAsBytes)
	key := &ecdsa.PrivateKey{
		D: d,
	}
	return key, nil
}

// convert public key to string
func PublicKeyToString(publicKey *ecdsa.PublicKey) string {
	pubKeyBytes := curve.PointToBytes(publicKey)
	return hex.EncodeToString(pubKeyBytes)
}

// convert public key string to key
func PublicKeyStrToKey(pubKey string) (*ecdsa.PublicKey, error) {
	pubKeyAsBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return nil, err
	}
	x, y := elliptic.Unmarshal(curve.CURVE, pubKeyAsBytes)
	key := &ecdsa.PublicKey{
		Curve: curve.CURVE,
		X:     x,
		Y:     y,
	}
	return key, nil
}
