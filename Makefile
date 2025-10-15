.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: test
test: fmt
	go test -v ./...

.PHONY: test-coverage
test-coverage: fmt
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

.PHONY: test-short
test-short: fmt
	go test -v -short ./...

.PHONY: clean
clean:
	rm -f coverage.out coverage.html
