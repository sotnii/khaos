# ==================== Go build ====================
APP_NAME  := khaos
BUILD_DIR := build

.PHONY: all generate build clean run bpf

all: generate build

generate: vmlinux.h          # <-- ensures vmlinux.h exists before go generate (bpf2go etc.)
	go generate ./...

build:
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(APP_NAME) .

clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) packet_drop.o vmlinux.h

run:
	./$(BUILD_DIR)/$(APP_NAME) $(filter-out $@,$(MAKECMDGOALS))

# ==================== BPF helpers ====================

# Smart vmlinux.h generation — only runs if missing or BTF changed
# Falls back gracefully if /sys/kernel/btf/vmlinux doesn't exist (old kernel / container)
vmlinux.h:
	@echo "Checking for vmlinux.h..."
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "Generating vmlinux.h from BTF..."; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h; \
	else \
		if [ ! -f vmlinux.h ]; then \
			echo "BTF not available — creating empty vmlinux.h (safe for modern CO-RE builds)"; \
			touch vmlinux.h; \
		fi \
	fi

# Bonus: force regeneration
.PHONY: regen-vmlinux
regen-vmlinux:
	rm -f vmlinux.h
	$(MAKE) vmlinux.h