.PHONY: build test clean run

BINARY_NAME=bypass-proxy

build:
	go build -o $(BINARY_NAME) ./cmd/proxy

test:
	go test -v ./...

check: build
	./$(BINARY_NAME) -test

run: build
	./$(BINARY_NAME)

run-no-sysproxy: build
	./$(BINARY_NAME) -sysproxy=false

clean:
	rm -f $(BINARY_NAME)
