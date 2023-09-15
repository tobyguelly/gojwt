package main

import "github.com/tobyguelly/gojwt"

func main() {
	gojwt.Algorithms = gojwt.AlgorithmMap{
		gojwt.AlgHS256: func(message, secret string) (string, error) {
			// TODO Custom Implementation
			return "", nil
		},
	}
}
