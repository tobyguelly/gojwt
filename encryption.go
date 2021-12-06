package gojwt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
)

var (
	algorithms = map[string]func(message, secret string) (string, error){
		AlgHS256: SignHS256,
		AlgHS384: SignHS384,
		AlgHS512: SignHS512,
	}
	encryptionAlgorithms = map[string]func(message string, label []byte, key rsa.PublicKey) (string, error){
		AlgRS256: EncryptRS256,
		AlgRS384: EncryptRS384,
		AlgRS512: EncryptRS512,
	}
	decryptionAlgorithms = map[string]func(message string, label []byte, key rsa.PrivateKey) (string, error){
		AlgRS256: DecryptRS256,
		AlgRS384: DecryptRS384,
		AlgRS512: DecryptRS512,
	}
)

// EncodeBase64 encodes a string with the base64 algorithm.
func EncodeBase64(message string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(message))
}

// DecodeBase64 decodes a string with the base64 algorithm.
func DecodeBase64(message string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(message)
}

func signHS(algorithm func() hash.Hash, message, secret string) (string, error) {
	key := []byte(secret)
	h := hmac.New(algorithm, key)
	_, err := h.Write([]byte(message))
	if err != nil {
		return "", err
	}
	return EncodeBase64(string(h.Sum(nil))), nil
}

// SignHS256 signs a message string with a secret string using the HS256 algorithm
// with additional base64 rawURLEncoding of the result hash.
func SignHS256(message, secret string) (string, error) {
	return signHS(sha256.New, message, secret)
}

// SignHS384 signs a message string with a secret string using the HS384 algorithm
// with additional base64 rawURLEncoding of the result hash.
func SignHS384(message, secret string) (string, error) {
	return signHS(sha512.New384, message, secret)
}

// SignHS512 signs a message string with a secret string using the HS512 algorithm
// with additional base64 rawURLEncoding of the result hash.
func SignHS512(message, secret string) (string, error) {
	return signHS(sha512.New, message, secret)
}

func encryptRS(hash hash.Hash, message string, label []byte, publicKey rsa.PublicKey) (string, error) {
	cipher, err := rsa.EncryptOAEP(hash, rand.Reader, &publicKey, []byte(message), label)
	if err != nil {
		return "", err
	}
	return EncodeBase64(string(cipher)), nil
}

func decryptRS(hash hash.Hash, encodedCipher string, label []byte, privateKey rsa.PrivateKey) (string, error) {
	cipher, err := DecodeBase64(encodedCipher)
	if err != nil {
		return "", err
	}
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, &privateKey, cipher, label)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// EncryptRS256 signs a message string with a secret string and an RSA public key using the RS256 algorithm
// with additional base64 rawURLEncoding of the result cipher.
func EncryptRS256(message string, label []byte, publicKey rsa.PublicKey) (string, error) {
	return encryptRS(sha256.New(), message, label, publicKey)
}

// DecryptRS256 decrypts a base64 rawUrlEncoded cipher string with a secret string and an RSA private key
// using the RS256 algorithm.
func DecryptRS256(encodedCipher string, label []byte, privateKey rsa.PrivateKey) (string, error) {
	return decryptRS(sha256.New(), encodedCipher, label, privateKey)
}

// EncryptRS384 signs a message string with a secret string and an RSA public key using the RS384 algorithm
// with additional base64 rawURLEncoding of the result cipher.
func EncryptRS384(message string, label []byte, publicKey rsa.PublicKey) (string, error) {
	return encryptRS(sha512.New384(), message, label, publicKey)
}

// DecryptRS384 decrypts a base64 rawUrlEncoded cipher string with a secret string and an RSA private key
// using the RS384 algorithm.
func DecryptRS384(encodedCipher string, label []byte, privateKey rsa.PrivateKey) (string, error) {
	return decryptRS(sha512.New384(), encodedCipher, label, privateKey)
}

// EncryptRS512 signs a message string with a secret string and an RSA public key using the RS512 algorithm
// with additional base64 rawURLEncoding of the result cipher.
func EncryptRS512(message string, label []byte, publicKey rsa.PublicKey) (string, error) {
	return encryptRS(sha512.New(), message, label, publicKey)
}

// DecryptRS512 decrypts a base64 rawUrlEncoded cipher string with a secret string and an RSA private key
// using the RS512 algorithm.
func DecryptRS512(encodedCipher string, label []byte, privateKey rsa.PrivateKey) (string, error) {
	return decryptRS(sha512.New(), encodedCipher, label, privateKey)
}
