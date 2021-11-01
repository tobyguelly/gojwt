# GoJWT - JSON Web Tokens in Go
[![GoReportCard](https://goreportcard.com/badge/github.com/tobyguelly/gojwt)](https://goreportcard.com/report/github.com/tobyguelly/gojwt)
[![GoDoc](https://godoc.org/github.com/tobyguelly/gojwt?status.svg)](https://godoc.org/github.com/tobyguelly/gojwt)
![BuildStatus](https://img.shields.io/github/workflow/status/tobyguelly/gojwt/Run%20Unit%20Tests)
[![Code Coverage](https://gocover.io/_badge/github.com/tobyguelly/gojwt)](https://gocover.io/github.com/tobyguelly/gojwt)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://raw.githubusercontent.com/tobyguelly/gojwt/main/LICENSE)

GoJWT is a simple and lightweight library for creating, formatting, manipulating, signing and validating Json Web Tokens in GoLang, used for token-based authentication. Specified in [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)

## Installation
```
go get -u github.com/tobyguelly/gojwt
```

## Examples

### Creating JWTs
- You can create JWTs using the `JWT` struct
- Then you can format them into a JWT using the `String()` method
```go
jwt := gojwt.JWT {
	Header:  gojwt.DefaultHeader,
	Payload: gojwt.Payload {
		Issuer:  "1208202852",
		Subject: "1927027602",
	},
}
fmt.Println(jwt.String()) // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIxMjA4MjAyODUyIiwic3ViIjoiMTkyNzAyNzYwMiJ9.-BUwqkL2DFgHTSaAdVsnrppM9R2QkpAGlpZp3N2Wir4
```

### Custom fields in the JWT payload
- Custom fields can be applied to the JWT `Payload` by setting the `Custom` property to a map
```go
jwt.Payload.Custom = map[string]interface{}{
	"Hello": "World",
}
```

### Signing and Validating JWTs
- JWTs can be signed and validated with a secret string
- The error returned by the `Validate()` method indicates, whether the validation was successful or not
  - If the token is valid using the given secret, `nil` is returned
  - If the token has not been signed yet, the error `ErrTokNotSig` is returned
  - If an invalid secret was passed, the error `ErrInvSecKey` is returned
  - If the signature algorithm given in the JWT `Header` is not supported, the error `ErrAlgNotImp` is returned
```go
err := jwt.Sign("mysecret")
if err == nil {
	fmt.Println("JWT successfully signed!")
}
err := jwt.Validate("mysecret")
if err == nil {
	fmt.Println("JWT successfully validated!")
}
```

### Loading JWTs
- Parsed JWTs can be loaded by using the `NewJWT` function
  - If the given string is not a valid JWT, an error is returned
```go
jwt, err := gojwt.NewJWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiIxMjA4MjAyODUyIiwic3ViIjoiMTkyNzAyNzYwMiJ9.-BUwqkL2DFgHTSaAdVsnrppM9R2QkpAGlpZp3N2Wir4")
if err == nil {
	fmt.Println("JWT successfully loaded!")
}
```

### Additional Encoding for Signature
- You can additionally base64 encode/decode the `Signature` property of the JWT
```go
jwt.EncodeSignature()
err := jwt.DecodeSignature()
if err == nil {
	fmt.Println("JWT signature decoded!")
}
```
