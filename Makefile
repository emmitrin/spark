.PHONY: build proto clean test

build:
	@mkdir -p bin
	go build -o bin/worker ./cmd/worker

proto:
	@which protoc > /dev/null || (echo "protoc not found. Install protobuf compiler: https://grpc.io/docs/protoc-installation/" && exit 1)
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		pkg/proto/worker.proto

clean:
	rm -rf bin/
	rm -f pkg/proto/*.pb.go
	rm -f internal/monitor/ebpf/bpf/*.o

test:
	go test ./...

test-ebpf:
	@echo "Building eBPF test POC..."
	@go build -o bin/test_ebpf ./cmd/test_ebpf
	@echo "Run with: sudo ./bin/test_ebpf"

run:
	./bin/worker --config config.yaml
