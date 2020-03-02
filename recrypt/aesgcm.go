package recrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"io"
	"os"
)

func GCMEncrypt(plaintext string, key string, iv []byte, additionalData []byte) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ciphertext := aesgcm.Seal(nil, iv, []byte(plaintext), additionalData)
	return hex.EncodeToString(ciphertext), nil
}

func GCMDecrypt(ct string, key string, iv []byte, additionalData []byte) (string, error) {
	ciphertext, _ := hex.DecodeString(ct)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := aesgcm.Open(nil, iv, ciphertext, additionalData)
	if err != nil {
		return "", err
	}
	s := string(plaintext[:])
	return s, nil
}

func FileEncryption(key string, infileName string, iv []byte, encfileName string) {
	inFile, err := os.Open(infileName)
	if err != nil {
		panic(err)
	}
	defer inFile.Close()
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}
	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.  var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])
	outFile, err := os.OpenFile(encfileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	writer := &cipher.StreamWriter{S: stream, W: outFile}
	// Copy the input file to the output file, encrypting as we go.
	if _, err := io.Copy(writer, inFile); err != nil {
		panic(err)
	}
}

func FileDecryption(key string, encfileName string, iv []byte, decfileName string) {
	inFile, err := os.Open(encfileName)
	if err != nil {
		panic(err)
	}
	defer inFile.Close()
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}
	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.  var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])
	outFile, err := os.OpenFile(decfileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()
	reader := &cipher.StreamReader{S: stream, R: inFile}
	// Copy the input file to the output file, decrypting as we go.
	if _, err := io.Copy(outFile, reader); err != nil {
		panic(err)
	}
}
