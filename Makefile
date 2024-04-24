.PHONY: lint unit-tests
lint:
	golangci-lint run

unit-tests:
	go test -tags sqlite -v -race -coverprofile=coverage.txt -covermode=atomic ./...