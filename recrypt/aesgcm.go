package recrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"os"
)

func GCMEncrypt(plaintext []byte, key string, iv []byte, additionalData []byte) (cipherText []byte, err error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	cipherText = aesgcm.Seal(nil, iv, plaintext, additionalData)
	return cipherText, nil
}

func GCMDecrypt(cipherText []byte, key string, iv []byte, additionalData []byte) (plainText []byte, err error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plainText, err = aesgcm.Open(nil, iv, cipherText, additionalData)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func OFBFileEncrypt(key string, iv []byte, infileName string, encfileName string) (err error) {
	inFile, err := os.Open(infileName)
	if err != nil {
		panic(err)
	}
	defer inFile.Close()
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.  var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])
	outFile, err := os.OpenFile(encfileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()

	writer := &cipher.StreamWriter{S: stream, W: outFile}
	// Copy the input file to the output file, encrypting as we go.
	if _, err := io.Copy(writer, inFile); err != nil {
		return err
	}
	return nil
}

func OFBFileDecrypt(key string, iv []byte, encfileName string, decfileName string) (err error) {
	inFile, err := os.Open(encfileName)
	if err != nil {
		return err
	}
	defer inFile.Close()
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	// If the key is unique for each ciphertext, then it's ok to use a zero
	// IV.  var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])
	outFile, err := os.OpenFile(decfileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()
	reader := &cipher.StreamReader{S: stream, R: inFile}
	// Copy the input file to the output file, decrypting as we go.
	if _, err = io.Copy(outFile, reader); err != nil {
		return err
	}
	return nil
}
