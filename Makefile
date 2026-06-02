APP=amon

build:
	@go build -o bin/$(APP) ./cmd/amon/

gen:
	@clang -target bpf -g -O2 -c bpf/trace.c -o internal/bpf/trace.o

run: build
	@sudo bin/$(APP)

script:
	@chmod +x ./scripts/script.sh
	@./scripts/script.sh

clean:
	@rm -r ./internal/bpf/*
	@rm -r ./bin/*