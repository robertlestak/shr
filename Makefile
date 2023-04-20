
 

VERSION=v0.0.1

bin: bin/shr_darwin bin/shr_linux bin/shr_windows

bin/shr_darwin:
	mkdir -p bin
	GOOS=darwin GOARCH=amd64 go build -ldflags="-X 'main.Version=$(VERSION)'" -o bin/shr_darwin cmd/shr/*.go
	openssl sha512 bin/shr_darwin > bin/shr_darwin.sha512

bin/shr_linux:
	mkdir -p bin
	GOOS=linux GOARCH=amd64 go build -ldflags="-X 'main.Version=$(VERSION)'" -o bin/shr_linux cmd/shr/*.go
	openssl sha512 bin/shr_linux > bin/shr_linux.sha512

bin/shr_windows:
	mkdir -p bin
	GOOS=windows GOARCH=amd64 go build -ldflags="-X 'main.Version=$(VERSION)'" -o bin/shr_windows cmd/shr/*.go
	openssl sha512 bin/shr_windows > bin/shr_windows.sha512

.PHONY: docker
docker:
	docker build -t shr .