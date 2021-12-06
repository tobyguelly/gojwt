package gojwt

import (
	"encoding/json"
	"strings"
)

// Payload is the payload section of the JWT token.
type Payload struct {

	// Issuer is the issuer claim in the JWT token.
	Issuer string `json:"iss,omitempty"`

	// Subject is the subject claim in the JWT token.
	Subject string `json:"sub,omitempty"`

	// Audience is the audience claim in the JWT token.
	Audience string `json:"aud,omitempty"`

	// ExpirationTime is the expiration time claim in the JWT token.
	ExpirationTime string `json:"exp,omitempty"`

	// NotBefore is the not before claim in the JWT token.
	NotBefore string `json:"nbf,omitempty"`

	// IssuedAt is the issued at claim in the JWT token.
	IssuedAt string `json:"iat,omitempty"`

	// JWTID is the JWT id claim in the JWT token.
	JWTID string `json:"jti,omitempty"`

	// Custom is a map containing custom keys and claims for the JWT token.
	Custom map[string]interface{} `json:"-"`
}

// IsEmpty returns a bool, whether the Payload is empty or not.
func (p *Payload) IsEmpty() bool {
	empty := Payload{}
	resThis, _ := p.Json()
	resEmpty, _ := empty.Json()
	return resThis == resEmpty
}

// SetCustom sets a key and a value in the Custom values.
func (p *Payload) SetCustom(key string, value interface{}) *Payload {
	if p.Custom == nil {
		p.Custom = make(map[string]interface{})
	}
	p.Custom[key] = value
	return p
}

// GetCustom returns a field in the Custom values, identified by the key.
func (p *Payload) GetCustom(key string) interface{} {
	return p.Custom[key]
}

// Json formats the Payload into JSON format.
func (p *Payload) Json() (string, error) {
	preRes, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	data := string(preRes)
	if len(p.Custom) > 0 {
		data = strings.TrimSuffix(data, "}")
		res, err := json.Marshal(p.Custom)
		if err != nil {
			return "", err
		}
		if string(preRes) != "{}" {
			data += ","
		}
		data += strings.TrimPrefix(string(res), "{")
	}
	return data, err
}

func (p *Payload) applyFields(fields map[string]interface{}) {
	if len(fields) > 0 {
		for key, value := range fields {
			if _, exists := defaultFields[key]; !exists {
				p.SetCustom(key, value)
			}
		}
	}
}
