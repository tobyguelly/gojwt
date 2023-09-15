package gojwt

import (
	"encoding/json"
	"strings"
)

type Map map[string]interface{}

// Payload is the payload section of the JWT token.
type Payload struct {

	// Issuer is the issuer claim in the JWT token.
	Issuer string `json:"iss,omitempty"`

	// Subject is the subject claim in the JWT token.
	Subject string `json:"sub,omitempty"`

	// Audience is the audience claim in the JWT token.
	Audience string `json:"aud,omitempty"`

	// ExpirationTime is the expiration time claim in the JWT token.
	ExpirationTime *Time `json:"exp,omitempty"`

	// NotBefore is the not before claim in the JWT token.
	NotBefore *Time `json:"nbf,omitempty"`

	// IssuedAt is the issued at claim in the JWT token.
	IssuedAt *Time `json:"iat,omitempty"`

	// JWTID is the JWT id claim in the JWT token.
	JWTID string `json:"jti,omitempty"`

	// Custom is a map containing custom keys and claims for the JWT token.
	Custom Map `json:"-"`
}

// IsEmpty returns a bool, whether the Payload is empty or not.
func (this *Payload) IsEmpty() bool {
	empty := Payload{}
	resThis, _ := this.Json()
	resEmpty, _ := empty.Json()
	return resThis == resEmpty
}

// SetCustom sets a key and a value in the Map values.
func (this *Payload) SetCustom(key string, value interface{}) *Payload {
	if this.Custom == nil {
		this.Custom = make(map[string]interface{})
	}
	this.Custom[key] = value
	return this
}

// GetCustom returns a field in the Map values, identified by the key.
func (this *Payload) GetCustom(key string) interface{} {
	return this.Custom[key]
}

// Json formats the Payload into JSON format.
func (this *Payload) Json() (string, error) {
	preRes, err := json.Marshal(this)
	if err != nil {
		return "", err
	}
	data := string(preRes)
	if len(this.Custom) > 0 {
		data = strings.TrimSuffix(data, "}")
		res, err := json.Marshal(this.Custom)
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

func (this *Payload) applyCustom(fields map[string]interface{}) {
	if len(fields) > 0 {
		for key, value := range fields {
			if _, exists := defaultFields[key]; !exists {
				this.SetCustom(key, value)
			}
		}
	}
}
