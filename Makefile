build:
	@go build -o bin/filesvr

run: build
	@./bin/filesvr