all: build
build:
	go build -o ./bin/health-check ./cmd/health-check
clean:
	rm -f /bin/health-check
run:
	./bin/health-check
dev:
	make build && make run