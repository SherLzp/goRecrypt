package main

import "fmt"

func main() {
	_, pubKey := GenerateKeys()
	aPriKey, _ := GenerateKeys()
	cipherText, pubE, pubV, s := Encrypt("Hello", pubKey)
	fmt.Println(cipherText)
	fmt.Println(pubE)
	fmt.Println(pubV)
	fmt.Println(s)
	rk, pubX := ReKeyGen(aPriKey, pubKey)
	fmt.Println(rk)
	fmt.Println(pubX)
}
