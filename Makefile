# A3-PS022-TC177: Makefile

CLANG ?= /usr/lib/llvm21/bin/clang
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
BPF_CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include

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

.PHONY: all clean lab-setup lab-teardown bench bench-live sweep demo

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
	rm -f benchmark/results.json benchmark/results.csv
	rm -f benchmark/benchmark_results.png benchmark/sensitivity_results.png benchmark/sensitivity_results.txt

# Offline benchmark (uses hardcoded empirical data — no root needed)
bench: all
	@python3 benchmark/run_benchmarks.py --simulate
	@python3 benchmark/plot_results.py

# Live benchmark (requires root: sudo make bench-live)
bench-live: all
	@python3 benchmark/run_benchmarks.py
	@python3 benchmark/plot_results.py

# Parameter sensitivity sweep (requires root: sudo make sweep)
sweep: all
	@./scripts/sensitivity_sweep.sh

# Live 3-pane demo (requires root + tmux: sudo make demo)
demo: all
	@./scripts/demo.sh

# Setup / teardown helpers
lab-setup:
	@sudo ./scripts/setup_lab.sh

lab-teardown:
	@sudo ./scripts/teardown_lab.sh
