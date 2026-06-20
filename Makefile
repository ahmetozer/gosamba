.PHONY: build test test-race fmt vet tidy clean e2e-deps

e2e-deps:
	apt-get install -y smbclient

build:
	go build -o gosamba ./cmd/gosamba

test:
	go test ./...

test-race:
	go test -race ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -f gosamba
