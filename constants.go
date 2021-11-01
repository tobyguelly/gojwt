package gojwt

import "errors"

var (
	// ErrAlgNotImp indicates that the algorithm in the JWT header is not implemented
	ErrAlgNotImp = errors.New("SIGNATURE ALGORITHM NOT IMPLEMENTED")

	// ErrTokNotSig indicates that the JWT has not been signed yet, and therefore can't be validated
	ErrTokNotSig = errors.New("TOKEN NOT SIGNED/MISSING SIGNATURE")

	// ErrInvSecKey indicates that the JWT has failed a validation, because of an invalid secret key
	ErrInvSecKey = errors.New("INVALID SECRET")

	// ErrBadJWTTok indicates that a given string is not a valid JWT token
	ErrBadJWTTok = errors.New("NOT A JWT/BAD JWT")
)

var (
	// DefaultHeader is the default header for JWT tokens using the HS256 algorithm
	DefaultHeader = Header{
		Algorithm: AlgHS256,
		Type:      TypJWT,
	}
)

var (
	defaultFields = map[string]string{
		"iss": "Issuer",
		"sub": "Subject",
		"aud": "Audience",
		"exp": "ExpirationTime",
		"nbf": "NotBefore",
		"iat": "IssuedAt",
		"jti": "JWTID",
	}
)

const (
	// AlgHS256 indicates that the JWT uses the HS256 algorithm for signing itself
	AlgHS256 = "HS256"
)

const (
	// TypJWT indicates that the token type is JWT
	TypJWT = "JWT"
)
