package main

import (
	"fmt"
)

func main() {
	aPriKey, aPubKey := GenerateKeys()
	bPriKey, bPubKey := GenerateKeys()
	cipherText, capsule := Encrypt("Hello", aPubKey)
	fmt.Println("ciphereText:", cipherText)
	rk, pubX := ReKeyGen(aPriKey, bPubKey)
	newCapsule := ReEncryption(rk, capsule)
	key := RecreateKey(bPriKey, newCapsule, &pubX)
	plainText := Decrypt(cipherText, key)
	fmt.Println(string(plainText))
}
