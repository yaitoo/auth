package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
)

const (
	dicAlpha       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	dicNumber      = "0123456789"
	dicAlphaNumber = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

func randStr(n int, dic string) string {
	var bytes = make([]byte, n)
	rand.Read(bytes) // nolint: errcheck

	for k, v := range bytes {
		bytes[k] = dic[v%byte(len(dic))]
	}
	return string(bytes)
}

func generateHash(h hash.Hash, source, salt string) string {
	h.Write([]byte(source)) // nolint: errcheck
	if salt != "" {
		h.Write([]byte(salt)) // nolint: errcheck
	}

	return hex.EncodeToString(h.Sum(nil))
}

func verifyHash(h hash.Hash, hash string, source, salt string) bool {
	v := generateHash(h, source, salt)
	return hash == v
}

func getJWTKey(key string) []byte {
	return sha256.New().Sum([]byte(key))
}

func getAESKey(key string) []byte {
	return sha256.New().Sum([]byte(key))[0:32]
}

func encryptText(plainText []byte, key []byte) (string, error) {

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	return hex.EncodeToString(aesGCM.Seal(nonce, nonce, plainText, nil)), nil
}

func decryptText(cipherText string, key []byte) (string, error) {

	enc, _ := hex.DecodeString(cipherText)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, cipherBuf := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plainBuf, err := aesGCM.Open(nil, nonce, cipherBuf, nil)
	if err != nil {
		return "", err
	}

	return string(plainBuf), nil
}
