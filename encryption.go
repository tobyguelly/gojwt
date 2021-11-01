package gojwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

var (
	algorithms = map[string]func(message, secret string) (string, error){
		AlgHS256: SignHS256,
	}
)

// EncodeBase64 encodes a string with the base64 algorithm
func EncodeBase64(message string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(message))
}

// DecodeBase64 decodes a string with the base64 algorithm
func DecodeBase64(message string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(message)
}

// SignHS256 signs a message string with a secret string using the HS256 algorithm
// with additional base64 rawURLEncoding of the result hash
func SignHS256(message, secret string) (string, error) {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	_, err := h.Write([]byte(message))
	if err != nil {
		return "", err
	}
	return EncodeBase64(string(h.Sum(nil))), nil
}
