# A3-PS022-TC177: Makefile

CLANG ?= /usr/lib/llvm21/bin/clang
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
BPF_CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include

BIN_DIR = bin
SRC_DIR = src
TRAFFIC_DIR = traffic

BPF_SRC = $(SRC_DIR)/xdp_dns_ratelimit.bpf.c
BPF_OBJ = $(SRC_DIR)/xdp_dns_ratelimit.bpf.o
LOADER_SRC = $(SRC_DIR)/loader.c
LOADER_BIN = $(SRC_DIR)/loader
DNS_SERVER_SRC = $(SRC_DIR)/dns_server.c
DNS_SERVER_BIN = $(SRC_DIR)/dns_server
FLOODER_SRC = $(TRAFFIC_DIR)/flood_generator.c
FLOODER_BIN = $(TRAFFIC_DIR)/flood_generator

TARGETS = $(BPF_OBJ) $(LOADER_BIN) $(DNS_SERVER_BIN) $(FLOODER_BIN)

.PHONY: all clean lab-setup lab-teardown bench

all: $(TARGETS)

$(BPF_OBJ): $(BPF_SRC) include/common.h include/dns_packet.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(LOADER_BIN): $(LOADER_SRC) include/common.h
	$(CC) $(CFLAGS) $< -lbpf -o $@

$(DNS_SERVER_BIN): $(DNS_SERVER_SRC) include/dns_packet.h
	$(CC) $(CFLAGS) $< -o $@

$(FLOODER_BIN): $(FLOODER_SRC) include/dns_packet.h
	$(CC) $(CFLAGS) -pthread $< -o $@

clean:
	rm -f $(BPF_OBJ) $(LOADER_BIN) $(DNS_SERVER_BIN) $(FLOODER_BIN)
	rm -f benchmark/results.json benchmark/results.csv benchmark/benchmark_results.png

lab-setup:
	@sudo ./scripts/setup_lab.sh

lab-teardown:
	@sudo ./scripts/teardown_lab.sh

bench: all
	@python3 benchmark/run_benchmarks.py
	@python3 benchmark/plot_results.py
