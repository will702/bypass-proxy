.PHONY: build test clean run install

BINARY_NAME=bypass-proxy
INSTALL_DIR=$(HOME)/.local/bin

build:
	go build -o $(BINARY_NAME) ./cmd/proxy

install: build
	install -d $(INSTALL_DIR)
	install -m 755 $(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)

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
