CC = clang
# Homebrew builds with WERROR= so a newer compiler's new warnings do not break installs.
WERROR ?= -Werror
CFLAGS = -std=c11 -Wall -Wextra $(WERROR) -Wpedantic -mmacosx-version-min=13.0 -g
FRAMEWORKS = -framework IOKit -framework CoreFoundation -framework SystemConfiguration
NETIF_FRAMEWORKS = -framework CoreFoundation -framework SystemConfiguration
SOURCES = $(addprefix src/,main.c daemon.c session.c health.c control.c datapath.c status.c admin.c usb.c \
          netif.c rndis.c cli.c config.c log.c clock.c)
HEADERS = $(wildcard src/*.h)
VERSION := $(shell sed -n 's/^\#define VERSION "\(.*\)"/\1/p' src/config.h)

.PHONY: all check analyze dist clean
all: rndis-tether

rndis-tether: $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -O2 $(SOURCES) $(FRAMEWORKS) -o $@

# AddressSanitizer from Command Line Tools clang 15 aborts at startup on macOS 26,
# so out-of-bounds reads are caught by Guard Malloc instead: every allocation ends
# exactly at an unmapped page (MALLOC_STRICT_SIZE), and the fuzzer copies each input
# into an exact-size allocation. A second run puts the guard page in front instead.
TEST_CFLAGS = $(CFLAGS) -Isrc -O1 -fno-omit-frame-pointer -fsanitize=undefined -fno-sanitize-recover=all
GMALLOC = DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib MALLOC_STRICT_SIZE=1
TESTS = rndis-tether-selftest rndis-tether-controltest rndis-tether-sessiontest

# Pure parsers, the fuzzer, BPF records and the settings file.
SELFTEST = tests/selftest.c $(addprefix src/,config.c log.c rndis.c netif.c)
rndis-tether-selftest: $(SELFTEST) $(HEADERS)
	$(CC) $(TEST_CFLAGS) $(SELFTEST) $(NETIF_FRAMEWORKS) -o $@

# The control pump over a fake USB link.
CONTROLTEST = tests/controltest.c $(addprefix src/,control.c rndis.c log.c config.c)
rndis-tether-controltest: $(CONTROLTEST) $(HEADERS)
	$(CC) $(TEST_CFLAGS) $(CONTROLTEST) $(FRAMEWORKS) -o $@

# Data path, health (KEEPALIVE, RESET) and status over a fake USB link and control channel;
# the admin socket over a real one.
SESSIONTEST = tests/sessiontest.c $(addprefix src/,datapath.c health.c status.c admin.c rndis.c netif.c log.c config.c)
rndis-tether-sessiontest: $(SESSIONTEST) $(HEADERS)
	$(CC) $(TEST_CFLAGS) $(SESSIONTEST) $(FRAMEWORKS) -o $@

check: $(TESTS)
	for t in $(TESTS); do $(GMALLOC) ./$$t && $(GMALLOC) MALLOC_PROTECT_BEFORE=1 ./$$t || exit 1; done

# Diagnostic: creates feth60/feth61 and checks that BPF on the driver side sees
# what macOS sends (needs root). Not part of the daemon.
BPFTEST = tests/bpftest.c src/log.c src/netif.c
bpf-feth-test: $(BPFTEST) $(HEADERS)
	$(CC) $(CFLAGS) -Isrc -O1 $(BPFTEST) $(NETIF_FRAMEWORKS) -o $@

# Fails on any finding.
analyze:
	$(CC) --analyze -Xanalyzer -analyzer-output=text -Xanalyzer -analyzer-werror $(CFLAGS) $(SOURCES)

# Release archive: one universal (Apple silicon + Intel) binary, ad-hoc signed as arm64
# requires, plus its SHA-256. The fixed name serves .../releases/latest/download/.
dist: $(SOURCES) $(HEADERS)
	rm -rf dist && mkdir -p dist/pkg
	$(CC) $(CFLAGS) -O2 -arch arm64 -arch x86_64 $(SOURCES) $(FRAMEWORKS) -o dist/pkg/rndis-tether
	codesign --force --sign - dist/pkg/rndis-tether
	cp LICENSE dist/pkg/
	tar -czf dist/rndis-tether-macos.tar.gz -C dist/pkg rndis-tether LICENSE
	cd dist && shasum -a 256 rndis-tether-macos.tar.gz > rndis-tether-macos.tar.gz.sha256
	@echo "dist/rndis-tether-macos.tar.gz: rndis-tether $(VERSION), $$(lipo -archs dist/pkg/rndis-tether)"

clean:
	rm -rf rndis-tether $(TESTS) bpf-feth-test dist *.dSYM *.plist
