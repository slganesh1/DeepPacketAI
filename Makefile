# filepath: /Users/rudradevmandal/Documents/DeepPacketAI/Makefile
.PHONY: all clean build run

all: build

build:
	go build -ldflags -w -o ./bin/deep_packet_ai ./cmd/main.go

run: build
	./bin/deep_packet_ai

clean:
	rm -f ./bin/deep_packet_ai