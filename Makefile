lint:
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.42.1
	@golangci-lint run --config .golangci.yaml
.PHONY: lint

test:
	@go test \
		-shuffle=on \
		-count=1 \
		-race \
		-timeout=10m \
		./...
.PHONY: test
