
benchmark:
	@go test . -bench=.

test:
	@go test .

format:
	@go fmt ./...

coverage:
	@go test -cover -coverprofile=c.out
	@go tool cover -html=c.out -o coverage.html

clear:
	@rm -rf c.out
	@rm -rf coverage.html