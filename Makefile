## remoteTool - top-level Makefile
##
## Auto-discovers every .c under src/ and builds a single binary in build/.
## Header-only deps are tracked via -MMD so changing a header rebuilds users.

CC      ?= gcc
PKG_CFG ?= pkg-config
PKGS    := gtk+-3.0 libssh vte-2.91 freerdp3 freerdp-client3 winpr3

# We use a privately-built FreeRDP 3 (with channel plugin .so files
# patched to be dlopen-able). It lives at /opt/remotetool-freerdp so
# it doesn't shadow the apt-installed FreeRDP - that would break
# system xfreerdp3 and any other app that links libfreerdp3.so.
RT_FREERDP_PREFIX := /opt/remotetool-freerdp
# Pass PKG_CONFIG_PATH inline rather than via Make `export`: the
# $(shell) invocations below run during makefile parsing and don't
# always see exported Make variables, so we'd silently fall back to
# the system FreeRDP .pc files (apt-installed FreeRDP, no plugins).
RT_PC_PATH := $(RT_FREERDP_PREFIX)/lib/pkgconfig

WARN    := -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes \
           -Wmissing-prototypes -Wpointer-arith -Wcast-qual \
           -Wformat=2 -Wno-unused-parameter

CFLAGS  := -std=c11 $(WARN) -O2 -g -D_GNU_SOURCE -pthread \
           -Iinclude $(shell PKG_CONFIG_PATH=$(RT_PC_PATH) $(PKG_CFG) --cflags $(PKGS))
# RPATH so OUR binary picks the private FreeRDP at runtime regardless
# of ldconfig order - and so nothing else on the system pays a price
# for our presence.
LDFLAGS := -pthread $(shell PKG_CONFIG_PATH=$(RT_PC_PATH) $(PKG_CFG) --libs $(PKGS)) \
           -Wl,-rpath,$(RT_FREERDP_PREFIX)/lib

SRC_DIR   := src
BUILD_DIR := build
BIN       := $(BUILD_DIR)/remotetool

SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

.PHONY: all clean run

all: $(BIN)

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(DEPS)

run: $(BIN)
	./$(BIN)

clean:
	rm -rf $(BUILD_DIR)
