all: build
build:
	go build -o ./bin/health-check ./cmd/health-check
clean:
	rm -f /bin/health-check
run:
	sudo ./bin/health-check
dev:
	make build && make run