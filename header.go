package gojwt

import "encoding/json"

// Header is the header section of the JWT token.
type Header struct {

	// Algorithm is a string containing the identification of the algorithm used for signing a JWT.
	Algorithm string `json:"alg"`

	// ContentType indicates the content type of the token, not required.
	ContentType string `json:"cty,omitempty"`

	// Type indicates the type of the token, must be "JWT" for JWT tokens.
	Type string `json:"typ"`
}

// IsEmpty returns a bool, whether the Header is empty or not.
func (this *Header) IsEmpty() bool {
	return this.Algorithm == "" && this.Type == "" && this.ContentType == ""
}

// Json formats the Header into JSON format.
func (this *Header) Json() (string, error) {
	res, err := json.Marshal(this)
	return string(res), err
}
