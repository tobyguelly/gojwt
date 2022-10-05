package gojwt

import (
	"crypto/rsa"
	"time"
)

// Builder aims to wrap a JWT value to provide
// setters and chaining options for properties.
type Builder struct {
	JWT
}

// WithBuilder creates a new Builder with an empty JWT token.
func WithBuilder() *Builder {
	return &Builder{
		JWT: NewJWT(),
	}
}

// Issuer sets the issuer property of the JWT.
func (g *Builder) Issuer(iss string) *Builder {
	g.JWT.Payload.Issuer = iss
	return g
}

// Subject sets the subject property of the JWT.
func (g *Builder) Subject(sub string) *Builder {
	g.JWT.Payload.Subject = sub
	return g
}

// Audience sets the audience property of the JWT.
func (g *Builder) Audience(aud string) *Builder {
	g.JWT.Payload.Audience = aud
	return g
}

// ExpirationTime sets the expiration time property of the JWT.
func (g *Builder) ExpirationTime(exp *Time) *Builder {
	g.JWT.Payload.ExpirationTime = exp
	return g
}

// ExpiresIn sets the expiration time property of the JWT to the
// current time and adds a specified time.Duration value to it.
func (g *Builder) ExpiresIn(duration time.Duration) *Builder {
	g.JWT.Payload.ExpirationTime = Now().Add(duration)
	return g
}

// NotBefore sets the not before property of the JWT.
func (g *Builder) NotBefore(nbf *Time) *Builder {
	g.JWT.Payload.NotBefore = nbf
	return g
}

// IssuedAt sets the issued at property of the JWT.
func (g *Builder) IssuedAt(iat *Time) *Builder {
	g.JWT.Payload.IssuedAt = iat
	return g
}

// IssuedNow sets the issued at property of the JWT
// to the current timestamp.
func (g *Builder) IssuedNow() *Builder {
	g.JWT.Payload.IssuedAt = Now()
	return g
}

// JWTID sets the jwtid property of the JWT.
func (g *Builder) JWTID(jti string) *Builder {
	g.JWT.Payload.JWTID = jti
	return g
}

// Custom sets a custom property in the JWT.
func (g *Builder) Custom(key, value string) *Builder {
	g.JWT.Payload.SetCustom(key, value)
	return g
}

// Sign signs the JWT with a given secret and returns
// the signed JWT as a string or a possible error.
func (g *Builder) Sign(secret string) (string, error) {
	err := g.JWT.Sign(secret)
	if err != nil {
		return "", err
	}
	return g.JWT.Parse()
}

// SignWithKey signs the JWT with a given label and rsa.PublicKey and returns
// the signed JWT as a string or a possible error.
func (g *Builder) SignWithKey(label string, key rsa.PublicKey) (string, error) {
	err := g.JWT.SignWithKey(label, key)
	if err != nil {
		return "", err
	}
	return g.JWT.Parse()
}
