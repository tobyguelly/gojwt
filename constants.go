package gojwt

import "errors"

var (
	// ErrAlgNotImp indicates that the algorithm in the JWT header is not implemented for the signing/validating method.
	ErrAlgNotImp = errors.New("SIGNATURE ALGORITHM NOT IMPLEMENTED FOR METHOD")

	// ErrTokNotSig indicates that the JWT has not been signed yet, and therefore can't be validated.
	ErrTokNotSig = errors.New("TOKEN NOT SIGNED / MISSING SIGNATURE")

	// ErrInvSecKey indicates that the JWT has failed a validation, because of an invalid secret key.
	ErrInvSecKey = errors.New("INVALID SECRET")

	// ErrBadJWTTok indicates that a given string is not a valid JWT token.
	ErrBadJWTTok = errors.New("NOT A JWT / BAD JWT")

	// ErrInvTokPrd indicates that a given JWT has failed a validation.
	// This happened because of either the nbf (NotBefore) or exp (ExpirationTime) claim had invalid dates.
	ErrInvTokPrd = errors.New("TOKEN VALIDITY PERIOD EXPIRED OR NOT STARTED")

	// ErrPayFieldVal indicates that a given payload has failed field format validation.
	ErrPayFieldVal = errors.New("ONE OR MORE FIELDS PRODUCE A VALIDATION ERROR")
)

var (
	// DefaultHeader is the default header for JWT tokens using the HS256 algorithm.
	DefaultHeader = Header{
		Algorithm: AlgHS256,
		Type:      TypJWT,
	}
	// DefaultFieldLength is the default maximum length of payload fields.
	DefaultFieldLength = 255 // TODO
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
	// AlgHS256 indicates that the JWT uses the HS256 algorithm for signing the signature.
	AlgHS256 = "HS256"

	// AlgHS384 indicates that the JWT uses the HS256 algorithm for signing the signature.
	AlgHS384 = "HS384"

	// AlgHS512 indicates that the JWT uses the HS512 algorithm for signing the signature.
	AlgHS512 = "HS512"

	// AlgRS256 indicates that the JWT uses the RS256 algorithm for encrypting and decrypting the signature.
	AlgRS256 = "RS256"

	// AlgRS384 indicates that the JWT uses the RS384 algorithm for encrypting and decrypting the signature.
	AlgRS384 = "RS384"

	// AlgRS512 indicates that the JWT uses the RS512 algorithm for encrypting and decrypting the signature.
	AlgRS512 = "RS512"
)

const (
	// TypJWT indicates that the token type is JWT.
	TypJWT = "JWT"
)
