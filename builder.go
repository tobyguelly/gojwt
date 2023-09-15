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
func (this *Builder) Issuer(iss string) *Builder {
	this.JWT.Payload.Issuer = iss
	return this
}

// Subject sets the subject property of the JWT.
func (this *Builder) Subject(sub string) *Builder {
	this.JWT.Payload.Subject = sub
	return this
}

// Audience sets the audience property of the JWT.
func (this *Builder) Audience(aud string) *Builder {
	this.JWT.Payload.Audience = aud
	return this
}

// ExpirationTime sets the expiration time property of the JWT.
func (this *Builder) ExpirationTime(exp time.Time) *Builder {
	this.JWT.Payload.ExpirationTime = Wrap(exp)
	return this
}

// ExpiresIn sets the expiration time property of the JWT to the
// current time and adds a specified time.Duration value to it.
func (this *Builder) ExpiresIn(duration time.Duration) *Builder {
	this.JWT.Payload.ExpirationTime = Now().Add(duration)
	return this
}

// NotBefore sets the not before property of the JWT.
func (this *Builder) NotBefore(nbf time.Time) *Builder {
	this.JWT.Payload.NotBefore = Wrap(nbf)
	return this
}

// IssuedAt sets the issued at property of the JWT.
func (this *Builder) IssuedAt(iat time.Time) *Builder {
	this.JWT.Payload.IssuedAt = Wrap(iat)
	return this
}

// IssuedNow sets the issued at property of the JWT
// to the current timestamp.
func (this *Builder) IssuedNow() *Builder {
	this.JWT.Payload.IssuedAt = Now()
	return this
}

// JWTID sets the JWTID property of the JWT.
func (this *Builder) JWTID(jti string) *Builder {
	this.JWT.Payload.JWTID = jti
	return this
}

// Custom sets a custom property in the JWT.
func (this *Builder) Custom(key string, value interface{}) *Builder {
	this.JWT.Payload.SetCustom(key, value)
	return this
}

// Sign signs the JWT with a given secret and returns
// the signed JWT as a string or a possible error.
func (this *Builder) Sign(secret string) (string, error) {
	err := this.JWT.Sign(secret)
	if err != nil {
		return "", err
	}
	return this.JWT.Parse()
}

// SignWithKey signs the JWT with a given label and rsa.PublicKey and returns
// the signed JWT as a string or a possible error.
func (this *Builder) SignWithKey(label string, key rsa.PublicKey) (string, error) {
	err := this.JWT.SignWithKey(label, key)
	if err != nil {
		return "", err
	}
	return this.JWT.Parse()
}
