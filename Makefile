# Name of the Go module (optional)
APP_NAME := khaos
BUILD_DIR := build

.PHONY: all generate build clean run

all: generate build

generate:
	go generate ./...

build:
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(APP_NAME) .

clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

run:
	./$(BUILD_DIR)/$(APP_NAME) $(filter-out $@,$(MAKECMDGOALS))
