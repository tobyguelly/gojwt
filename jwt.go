package gojwt

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
)

// JWT is a struct holding the values a JWT.
type JWT struct {

	// Header is the JWT header field.
	Header Header

	// Payload is the JWT payload field.
	Payload Payload

	// Signature is a string holding the JWT Header and the JWT Payload encrypted with the algorithm of the JWT Header.
	// Signature = Header.Algorithm(Header.Json() + "." + Payload.Json(), SECRET)
	Signature string
}

// NewJWT creates a completely new JWT object with default values.
func NewJWT() JWT {
	return JWT{
		Header: DefaultHeader,
		Payload: Payload{
			Issuer: "gojwt",
		},
	}
}

// LoadJWT creates a JWT object from a JWT string.
// Returns empty JWT, ErrBadJWTTok if the JWT is not a valid JWT,
// or returns the JWT if everything was successful.
func LoadJWT(token string) (jwt *JWT, err error) {
	res := &JWT{}
	jwtParts := strings.Split(token, ".")
	if len(jwtParts) != 3 {
		return res, ErrBadJWTTok
	}
	rawHeader, err := DecodeBase64(jwtParts[0])
	if err != nil {
		return res, err
	}
	var header Header
	err = json.Unmarshal(rawHeader, &header)
	if err != nil {
		return res, err
	}
	res.Header = header
	rawPayload, err := DecodeBase64(jwtParts[1])
	if err != nil {
		return res, err
	}
	var payload Payload
	var payloadMap map[string]interface{}
	err = json.Unmarshal(rawPayload, &payload)
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(rawPayload, &payloadMap)
	if err != nil {
		return res, err
	}
	payload.applyCustom(payloadMap)
	res.Payload = payload
	res.Signature = jwtParts[2]
	return res, nil
}

// IsEmpty returns a bool, whether the Header and the Payload are empty or not.
func (this *JWT) IsEmpty() (empty bool) {
	return this.Header.IsEmpty() && this.Payload.IsEmpty()
}

// IsSigned returns a bool, whether the token has been signed already or not.
func (this *JWT) IsSigned() (signed bool) {
	return this.Signature != ""
}

// IsExpired returns a bool, whether the token has already expired or is not valid yet.
func (this *JWT) IsExpired() (expired bool) {
	return (this.Payload.ExpirationTime != nil && this.Payload.ExpirationTime.Unix() <= Now().Unix()) ||
		(this.Payload.NotBefore != nil && this.Payload.NotBefore.Unix() >= Now().Unix())
}

// Validate validates a JWT based on a given secret string using a symmetric encryption algorithm.
// Returns ErrAlgNotImp if the algorithm in the Header is not implemented yet,
// ErrTokNotSig if the token has not been signed yet, ErrInvTokPrd if the token period has expired
// and ErrInvSecKey if the entered secret string is invalid corresponding to the signature.
// Returns nil if the JWT is validated with the entered secret.
func (this *JWT) Validate(secret string) (err error) {
	res, err := this.Data()
	if err != nil {
		return err
	}
	algorithm, exists := Algorithms[this.Header.Algorithm]
	if !exists {
		return ErrAlgNotImp
	}
	if !this.IsSigned() {
		return ErrTokNotSig
	}
	signature, err := algorithm(res, secret)
	if err != nil {
		return err
	}
	if signature == this.Signature {
		if this.IsExpired() {
			return ErrInvTokPrd
		}
		return nil
	}
	return ErrInvSecKey
}

// ValidateWithKey validates a JWT based on a given secret string using an asymmetric encryption algorithm
// Returns ErrAlgNotImp if the algorithm in the Header is not implemented yet,
// ErrTokNotSig if the token has not been signed yet, ErrInvTokPrd if the token period has expired
// and ErrInvSecKey if the entered key and/or label is invalid corresponding to the signature.
// Returns nil if the JWT is validated with the entered key.
func (this *JWT) ValidateWithKey(label string, key rsa.PrivateKey) (err error) {
	res, err := this.Data()
	if err != nil {
		return err
	}
	algorithm, exists := DecryptionAlgorithms[this.Header.Algorithm]
	if !exists {
		return ErrAlgNotImp
	}
	if !this.IsSigned() {
		return ErrTokNotSig
	}
	result, err := algorithm(this.Signature, []byte(label), key)
	if err != nil {
		if errors.Is(err, rsa.ErrDecryption) {
			return ErrInvSecKey
		}
		return err
	}
	if res == result {
		if this.IsExpired() {
			return ErrInvTokPrd
		}
		return nil
	}
	return ErrInvSecKey
}

// Sign signs a JWT using a symmetric encryption algorithm and creates the Signature,
// saved in the JWT. This method overwrites the Signature field in the JWT if it exists.
// Returns ErrAlgNotImp if the algorithm in the Header is not implemented yet or an asymmetric encryption algorithm.
// or returns ErrInvTokPrd if the token period has expired before signing.
func (this *JWT) Sign(secret string) (err error) {
	res, err := this.Data()
	if err != nil {
		return err
	}
	algorithm, exists := Algorithms[this.Header.Algorithm]
	if !exists {
		return ErrAlgNotImp
	}
	this.Signature, err = algorithm(res, secret)
	return err
}

// SignWithKey signs a JWT using an asymmetric encryption algorithm and creates the Signature,
// saved in the JWT. This method overwrites the Signature field in the JWT if it exists.
// Returns ErrAlgNotImp if the algorithm in the Header is not implemented yet or a symmetric encryption algorithm
// or returns ErrInvTokPrd if the token period has expired before signing.
func (this *JWT) SignWithKey(label string, key rsa.PublicKey) (err error) {
	res, err := this.Data()
	if err != nil {
		return err
	}
	algorithm, exists := EncryptionAlgorithms[this.Header.Algorithm]
	if !exists {
		return ErrAlgNotImp
	}
	this.Signature, err = algorithm(res, []byte(label), key)
	return err
}

// Parse formats the JWT into a JWT string and returns the result.
// It requires the token to be signed and the payload and header
// to be parsed successfully, otherwise it returns ErrTokNotSig.
// Result = Base64Encode(Header.Json()) + "." + Base64Encode(Payload.Json()) + "." + Signature
func (this *JWT) Parse() (token string, err error) {
	data, err := this.Data()
	if err != nil {
		return "", err
	}
	if !this.IsSigned() {
		return "", ErrTokNotSig
	}
	return data + "." + this.Signature, nil
}

// String formats the JWT into a JWT string and ignores probable errors.
// To parse tokens in production environments, it is recommended to use the Parse method.
func (this *JWT) String() (token string) {
	result, _ := this.Parse()
	return result
}

// GoString is the implementation for the GoStringer interface and an alias for String
func (this *JWT) GoString() (token string) {
	return this.String()
}

// SignParse performs the Sign and Parse operations in one single step.
func (this *JWT) SignParse(secret string) (token string, err error) {
	err = this.Sign(secret)
	if err != nil {
		return "", err
	}
	return this.Parse()
}

// SignParseWithKey performs the SignWithKey and Parse operations in one single step.
func (this *JWT) SignParseWithKey(label string, key rsa.PublicKey) (token string, err error) {
	err = this.SignWithKey(label, key)
	if err != nil {
		return "", err
	}
	return this.Parse()
}

// Data formats the Header and Payload fields of a JWT into a string.
// Result = Base64Encode(Header.Json()) + "." + Base64Encode(Payload.Json())
func (this *JWT) Data() (data string, err error) {
	header, err := this.Header.Json()
	if err != nil {
		return "", err
	}
	payload, err := this.Payload.Json()
	if err != nil {
		return "", err
	}
	return strings.Join(
		[]string{
			EncodeBase64(header),
			EncodeBase64(payload),
		},
		".",
	), nil
}
