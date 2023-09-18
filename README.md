# GoJWT - JSON Web Tokens in Go
[![GoReportCard](https://goreportcard.com/badge/github.com/tobyguelly/gojwt)](https://goreportcard.com/report/github.com/tobyguelly/gojwt)
[![GoDoc](https://godoc.org/github.com/tobyguelly/gojwt?status.svg)](https://godoc.org/github.com/tobyguelly/gojwt)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/tobyguelly/gojwt/test.yml)](https://github.com/tobyguelly/gojwt/actions)
[![CodeFactor](https://www.codefactor.io/repository/github/tobyguelly/gojwt/badge)](https://www.codefactor.io/repository/github/tobyguelly/gojwt)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://raw.githubusercontent.com/tobyguelly/gojwt/main/LICENSE)
<!--- [![Code Coverage](https://gocover.io/_badge/github.com/tobyguelly/gojwt)](https://gocover.io/github.com/tobyguelly/gojwt) --->

GoJWT is a simple and lightweight library for creating, formatting, manipulating, signing and validating [JSON Web Tokens](https://jwt.io) in Golang, used for token-based authorization. As specified in [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519), this library provides standard encryption algorithms and claim checks.

## Installation
```
go get -u github.com/tobyguelly/gojwt
```

## Supported Algorithms
`HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`

## Examples

### Creating JWTs
- You can create JWTs using the `NewJWT` function
- Then you can format and sign them into a JWT using the `SignParse()` method
```go
jwt := gojwt.NewJWT()
jwt.Payload.SetCustom("username", "admin")
token, err := jwt.SignParse("mysecret")
if err == nil {
    fmt.Println(token)
}
```
- Alternatively you can use JWT builders to create tokens more easily
```go
token, err := gojwt.WithBuilder().
    Custom("username", "admin").
    ExpiresIn(time.Second * 10).
    Sign(secret)
if err == nil {
    fmt.Println(token)
}
```

### Custom Fields in the Token Payload
- Custom fields can be applied to the JWT `Payload` by setting the `Custom` property to a map
```go
jwt.Payload.Custom = gojwt.Map{
	"string": "Example String",
	"number": 1234,
}
```

### Signing and Validating Tokens
- JWTs can be signed and validated with a secret string with the `Sign()` and `Validate()` method
- Dependent of the `Algorithm` field in the JWT `Header`, a symmetric encryption algorithm will be chosen
- The error returned by the `Validate()` method indicates, whether the validation was successful or not
  - If the token is valid using the given secret, `nil` is returned
  - If the token has not been signed yet, the error `ErrTokNotSig` is returned
  - If an invalid secret was passed, the error `ErrInvSecKey` is returned
  - If the signature algorithm given in the JWT `Header` is not supported, the error `ErrAlgNotImp` is returned
  - If the token has expired or is not valid yet based on the `ExpirationTime` and `NotBefore` claims, `ErrInvTokPer` is returned
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

### Support for Asymmetric Encryption/Decryption
- JWTs can also be signed using public/private keys and asymmetric encryption by using the `SignWithKey()` and `ValidateWithKey()` method
- Dependent of the `Algorithm` field in the JWT `Header`, an asymmetric encryption/decryption algorithm will be chosen
- The same type of errors as for the symmetric encryption are returned by those methods
```go
privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
publicKey := privateKey.PublicKey

err := jwt.SignWithKey("", publicKey)
if err == nil {
	fmt.Println("JWT successfully signed using public key!")
}
err := jwt.ValidateWithKey("", *privateKey)
if err == nil {
	fmt.Println("JWT successfully validated using private key!")
}
```

### Loading Tokens
- Parsed JWTs can be loaded by using the `LoadJWT` function
  - If the given string is not a valid JWT, an error is returned
```go
jwt, err := gojwt.LoadJWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnb2p3dCIsInN1YiI6IkV4YW1wbGUgVG9rZW4ifQ.5UDIu1WUy20KEM_vGUBdYnOBDiwfA94_vYvE3cehGS8")
if err == nil {
	fmt.Println("JWT successfully loaded!")
}
```

### Token Timeouts
- Tokens can have an expiration and a starting timestamp which is set using the `NotBefore` and `ExpirationTime` properties in the payload
- Then the validation process automatically returns `ErrInvTokPer` if the timestamp in the `NotBefore` field has not passed yet or the `ExpirationTime` has passed
  - This error can be ignored, it is informational only
- If these properties are not set, tokens are valid from the second they are signed on and do not expire
```go
jwt.Payload.NotBefore = gojwt.Now().Add(time.Second * 5)
jwt.Payload.ExpirationTime = gojwt.Wrap(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
```
