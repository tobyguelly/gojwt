package gojwt

import (
	"crypto/rsa"
	"time"
)

type Builder struct {
	JWT
}

func WithBuilder() *Builder {
	return &Builder{
		JWT: NewJWT(),
	}
}

func (g *Builder) Issuer(iss string) *Builder {
	g.JWT.Payload.Issuer = iss
	return g
}

func (g *Builder) Subject(sub string) *Builder {
	g.JWT.Payload.Subject = sub
	return g
}

func (g *Builder) Audience(aud string) *Builder {
	g.JWT.Payload.Audience = aud
	return g
}

func (g *Builder) ExpirationTime(exp *Time) *Builder {
	g.JWT.Payload.ExpirationTime = exp
	return g
}

func (g *Builder) ExpiresIn(duration time.Duration) *Builder {
	g.JWT.Payload.ExpirationTime = Now().Add(duration)
	return g
}

func (g *Builder) NotBefore(nbf *Time) *Builder {
	g.JWT.Payload.NotBefore = nbf
	return g
}

func (g *Builder) IssuedAt(iat *Time) *Builder {
	g.JWT.Payload.IssuedAt = iat
	return g
}

func (g *Builder) IssuedNow() *Builder {
	g.JWT.Payload.IssuedAt = Now()
	return g
}

func (g *Builder) JWTID(jti string) *Builder {
	g.JWT.Payload.JWTID = jti
	return g
}

func (g *Builder) Custom(key, value string) *Builder {
	g.JWT.Payload.SetCustom(key, value)
	return g
}

func (g *Builder) Sign(secret string) (string, error) {
	err := g.JWT.Sign(secret)
	if err != nil {
		return "", err
	}
	return g.JWT.Parse()
}

func (g *Builder) SignWithKey(label string, key rsa.PublicKey) (string, error) {
	err := g.JWT.SignWithKey(label, key)
	if err != nil {
		return "", err
	}
	return g.JWT.Parse()
}
