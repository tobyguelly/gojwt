package gojwt

import (
	"encoding/json"
	"strings"
)

// JWT is a struct holding the values a JWT
type JWT struct {

	// Header is the JWT header field
	Header Header

	// Payload is the JWT payload field
	Payload Payload

	// Signature is a string holding the JWT Header and the JWT Payload encrypted with the algorithm of the JWT Header
	// Signature = Header.Algorithm(Header.Json() + "." + Payload.Json(), SECRET)
	Signature string
}

// NewJWT creates a JWT object from a jwt string
// Returns empty JWT, ErrBadJWTTok if the JWT is not a valid JWT,
// or returns the JWT if everything was successful.
func NewJWT(jwt string) (JWT, error) {
	res := JWT{}
	jwtParts := strings.Split(jwt, ".")
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
	payload.applyFields(payloadMap)
	res.Payload = payload
	res.Signature = jwtParts[2]
	return res, nil
}

// IsEmpty returns a bool, whether the Header and the Payload are empty or not
func (j *JWT) IsEmpty() bool {
	return j.Header.IsEmpty() && j.Payload.IsEmpty()
}

// DecodeSignature decodes the Signature of the JWT with the base64 algorithm
func (j *JWT) DecodeSignature() error {
	res, err := DecodeBase64(j.Signature)
	if err != nil {
		return err
	}
	j.Signature = string(res)
	return nil
}

// EncodeSignature encodes the Signature of the JWT with the base64 algorithm
func (j *JWT) EncodeSignature() {
	j.Signature = EncodeBase64(j.Signature)
}

// Validate validates a JWT based on a given secret string
// Returns ErrAlgNotImp if the algorithm in the Header is not implemented yet,
// ErrTokNotSig if the token has not been signed yet,
// and ErrInvSecKey if the entered secret string is invalid corresponding to the signature.
// Returns nil if the JWT is validated with the entered secret
func (j *JWT) Validate(secret string) error {
	res, err := j.Data()
	if err != nil {
		return err
	}
	algorithm, exists := algorithms[j.Header.Algorithm]
	if !exists {
		return ErrAlgNotImp
	}
	if j.Signature == "" {
		return ErrTokNotSig
	}
	signature, err := algorithm(res, secret)
	if err != nil {
		return err
	}
	if signature == j.Signature {
		return nil
	}
	return ErrInvSecKey
}

// Sign signs a JWT and creates the Signature, saved in the JWT
// This method overwrites the Signature field in the JWT if it exists
// Returns ErrAlgNotImp if the algorithm in the Header is not implemented yet
func (j *JWT) Sign(secret string) error {
	res, err := j.Data()
	if err != nil {
		return err
	}
	algorithm, exists := algorithms[j.Header.Algorithm]
	if !exists {
		return ErrAlgNotImp
	}
	j.Signature, err = algorithm(res, secret)
	return err
}

// String formats the JWT into a JWT string and returns the result
// If the token has not been signed yet, a signature is created using the SignHS256 algorithm and no secret
// Result = Base64Encode(Header.Json()) + "." + Base64Encode(Payload.Json()) + "." + Signature
func (j *JWT) String() string {
	data, _ := j.Data()
	if j.Signature == "" {
		algorithm := algorithms[j.Header.Algorithm]
		if algorithm == nil {
			algorithm = SignHS256
		}
		signature, err := algorithm(data, "")
		if err != nil {
			return data
		}
		j.Signature = signature
	}
	return data + "." + j.Signature
}

// Data formats the Header and Payload fields of a JWT into a string
// Result = Base64Encode(Header.Json()) + "." + Base64Encode(Payload.Json())
func (j *JWT) Data() (string, error) {
	header, err := j.Header.Json()
	if err != nil {
		return "", err
	}
	payload, err := j.Payload.Json()
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
