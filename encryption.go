package gojwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
)

type (
	AlgorithmMap           map[string]func(message, secret string) (string, error)
	SigningAlgorithmMap    map[string]func(message string, privateKey *rsa.PrivateKey) (string, error)
	ValidationAlgorithmMap map[string]func(message string, signature string, publicKey *rsa.PublicKey) error
)

var (
	Algorithms = AlgorithmMap{
		AlgHS256: SignHS256,
		AlgHS384: SignHS384,
		AlgHS512: SignHS512,
	}
	SigningAlgorithms = SigningAlgorithmMap{
		AlgRS256: SignRS256,
		AlgRS384: SignRS384,
		AlgRS512: SignRS512,
	}
	ValidationAlgorithms = ValidationAlgorithmMap{
		AlgRS256: ValidateRS256,
		AlgRS384: ValidateRS384,
		AlgRS512: ValidateRS512,
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

func signRS(hash crypto.Hash, message string, privateKey *rsa.PrivateKey) (string, error) {
	if !hash.Available() {
		return "", fmt.Errorf("hash %v not available", hash)
	}
	h := hash.New()
	_, _ = h.Write([]byte(message))
	digest := h.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hash, digest)
	if err != nil {
		return "", err
	}
	return EncodeBase64(string(signature)), nil
}

func validateRS(hash crypto.Hash, message string, signature string, publicKey *rsa.PublicKey) error {
	if !hash.Available() {
		return fmt.Errorf("hash %v not available", hash)
	}
	h := hash.New()
	_, _ = h.Write([]byte(message))
	digest := h.Sum(nil)
	decoded, err := DecodeBase64(signature)
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(publicKey, hash, digest, decoded)
}

// SignRS256 signs a message string with an RSA private key using the RS256 algorithm
// with additional base64 rawURLEncoding of the result signature.
func SignRS256(message string, privateKey *rsa.PrivateKey) (string, error) {
	return signRS(crypto.SHA256, message, privateKey)
}

// ValidateRS256 validates a base64 rawUrlEncoded signature string with an RSA public key
// using the RS256 algorithm.
func ValidateRS256(message string, signature string, publicKey *rsa.PublicKey) error {
	return validateRS(crypto.SHA256, message, signature, publicKey)
}

// SignRS384 signs a message string with an RSA private key using the RS384 algorithm
// with additional base64 rawURLEncoding of the result signature.
func SignRS384(message string, privateKey *rsa.PrivateKey) (string, error) {
	return signRS(crypto.SHA384, message, privateKey)
}

// ValidateRS384 validates a base64 rawUrlEncoded signature string with an RSA public key
// using the RS384 algorithm.
func ValidateRS384(message string, signature string, publicKey *rsa.PublicKey) error {
	return validateRS(crypto.SHA384, message, signature, publicKey)
}

// SignRS512 signs a message string with an RSA private key using the RS512 algorithm
// with additional base64 rawURLEncoding of the result signature.
func SignRS512(message string, privateKey *rsa.PrivateKey) (string, error) {
	return signRS(crypto.SHA512, message, privateKey)
}

// ValidateRS512 validates a base64 rawUrlEncoded signature string with an RSA public key
// using the RS512 algorithm.
func ValidateRS512(message string, signature string, publicKey *rsa.PublicKey) error {
	return validateRS(crypto.SHA512, message, signature, publicKey)
}
