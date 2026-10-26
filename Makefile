# Default setting: Disable Garbage Collector (GC)
ENABLE_GC ?= 0
# LTO currently triggers a TLS type mismatch inside libttak when linking ssh-chatter.
# Keep it opt-in so the default build remains stable.
ENABLE_LTO ?= 1

# The C compiler to use
CC := gcc

# Get the number of available CPU cores for parallel LTO processing
NPROC := $(shell nproc)
LTO_NPROC := $(shell nproc >/dev/null 2>&1 && nproc || echo 1)
LTO_JOBS := $(shell jobs=$$(( $(LTO_NPROC) / 4 )); if [ $$jobs -lt 1 ]; then jobs=1; fi; echo $$jobs)

# ==============================================================================
# CFLAGS: EXTREME Low-Latency and LTO Optimization Flags
# DANGER: Contains highly aggressive, potentially unsafe, and experimental flags.
# ==============================================================================
SRC_DIR := src
INCLUDE_DIR := include
BUILD_DIR := build
TTAK_DIR := lib/libttak
INIH_DIR := lib/inih
DOORGAME_DIR := lib/doorgame
# Prefer the bundled libttak so patched sources are used consistently.
TTAK_LIB := $(TTAK_DIR)/lib/libttak.a
CFLAGS_TTAK := -I $(TTAK_DIR)/include
LDFLAGS_TTAK :=

CFLAGS_LIBSSH := $(shell pkg-config --cflags libssh 2>/dev/null)
LDFLAGS_LIBSSH := $(shell pkg-config --libs libssh 2>/dev/null || echo "-lssh")

# If libcurl/libssh was built against a non-system OpenSSL (e.g. Homebrew,
# a custom prefix), linking against the system libcrypto can cause ABI
# version mismatches ("undefined reference to symbol@OPENSSL_3.x.0").
# Use pkg-config to find the actual OpenSSL lib dir and prepend it so the
# linker picks the right libcrypto/libssl.  If OpenSSL lives under /usr/lib
# or /lib (standard system install) no extra flags are needed.
OPENSSL_LIB_DIR := $(shell pkg-config --variable=libdir openssl 2>/dev/null)
ifneq ($(OPENSSL_LIB_DIR),)
ifeq ($(filter /usr/lib% /lib%,$(OPENSSL_LIB_DIR)),)
LDFLAGS_EXTRA += -L$(OPENSSL_LIB_DIR) -Wl,-rpath,$(OPENSSL_LIB_DIR)
endif
endif

CFLAGS_LIBCURL := $(shell pkg-config --cflags libcurl 2>/dev/null)
LDFLAGS_LIBCURL := $(shell pkg-config --libs libcurl 2>/dev/null || echo "-lcurl")

# NOTE: -march=native builds binaries tuned for the current host CPU and must
#       be rebuilt on any deployment target with a different microarchitecture.
#       For portable/container deployments use -march=x86-64 -mtune=generic.

# Optional third-party libraries for charset conversion
HAVE_UCHARDET := $(shell pkg-config --exists uchardet && echo 1 || echo 0)
HAVE_ICU := $(shell pkg-config --exists icu-uc && echo 1 || echo 0)

ifeq ($(HAVE_UCHARDET),1)
CFLAGS_UCHARDET := $(shell pkg-config --cflags uchardet)
LDFLAGS_UCHARDET := $(shell pkg-config --libs uchardet)
endif

ifeq ($(HAVE_ICU),1)
CFLAGS_ICU := $(shell pkg-config --cflags icu-uc)
LDFLAGS_ICU := $(shell pkg-config --libs icu-uc)
endif

CFLAGS = -std=c2x -Ofast \
              -Wno-error=deprecated-declarations -DSSH_CHATTER_USE_GC=$(ENABLE_GC) \
              $(if $(filter 1,$(HAVE_UCHARDET)),-DSSH_CHATTER_HAVE_UCHARDET $(CFLAGS_UCHARDET)) \
              $(if $(filter 1,$(HAVE_ICU)),-DSSH_CHATTER_HAVE_ICU $(CFLAGS_ICU)) \
              -I $(INCLUDE_DIR) -I $(INIH_DIR) -I $(DOORGAME_DIR)/include $(CFLAGS_TTAK) $(CFLAGS_LIBSSH) $(CFLAGS_LIBCURL) -I /usr/local/include -I/usr/include \
              -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=700 \
              -Wall -Wextra -Wshadow -Wformat=2 -Wundef -Wconversion -Wdouble-promotion \
              -fstack-protector-strong -fno-common \
              -fPIC -ftls-model=global-dynamic \
              -g \
              -D_FORTIFY_SOURCE=3 \
              -march=native -mtune=native \
              -fomit-frame-pointer \
              -fno-signed-zeros \
              -funroll-loops \
              -falign-functions=32 -falign-loops=32 -falign-jumps=32 -falign-labels=32 \
              -ftree-vectorize \
              -fno-math-errno -freciprocal-math \
              -fmerge-all-constants -fipa-pta -fdevirtualize-at-ltrans \
              -fpeel-loops -fweb \
              -fdata-sections -ffunction-sections \
              -fno-asynchronous-unwind-tables \
              -fstrict-aliasing -fno-trapping-math -fstrict-overflow \
              -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free \
              -fipa-pure-const -fipa-cp-clone \
              -floop-nest-optimize -fgraphite-identity -floop-interchange -floop-strip-mine -floop-block \
              -fno-semantic-interposition \
              -fprefetch-loop-arrays \
              -fivopts \
              -faggressive-loop-optimizations \
              -fipa-sra \
              -fmodulo-sched -fmodulo-sched-allow-regmoves \
              -ftracer \
              -fvisibility=hidden \
              -fno-plt \
              -funsafe-math-optimizations \
              -ftree-loop-vectorize -ftree-slp-vectorize \
              -fno-exceptions \
              -fdelete-null-pointer-checks \
              -MMD -MP

CFLAGS += $(CFLAGS_EXTRA)

# ==============================================================================
# LINKER FLAGS (LDFLAGS) - Extreme Security and Optimization
# ==============================================================================
COMMON_LDFLAGS = \
    -L/usr/local/lib \
    $(DOORGAME_DIR)/libdoorgame.a \
    -lpthread -ldl -lm -lcrypto -llz4 $(LDFLAGS_TTAK) $(LDFLAGS_LIBCURL) -lutil -lc \
    $(LDFLAGS_UCHARDET) $(LDFLAGS_ICU) \
    -Wl,-Ofast \
    -Wl,--hash-style=gnu \
    -Wl,--sort-common \
    -Wl,-z,relro \
    -Wl,-z,now \
    -Wl,-Bsymbolic \
    -Wl,--gc-sections \
    -Wl,--as-needed \
    -Wl,--relax \
    -Wl,--no-undefined \
    -Wl,--warn-execstack -Wl,-z,noexecstack \
    -Wl,-z,separate-code \
    -Wl,-z,stack-size=8388608 \
    -Wl,-z,combreloc \
    -Wl,--build-id=none

COMMON_LDFLAGS += $(LDFLAGS_EXTRA)

LDFLAGS = $(COMMON_LDFLAGS) $(LDFLAGS_LIBSSH)

ifeq ($(ENABLE_LTO),1)
CFLAGS += -flto=$(LTO_JOBS) -fuse-linker-plugin
COMMON_LDFLAGS += -flto=$(LTO_JOBS) -fuse-linker-plugin
endif

# Sanitizer build for tests: `make SANITIZE=address,undefined unit-test`.
# Uses its own build directory and drops the flags that hide bugs from the
# sanitizers (aggressive optimisation, omitted frame pointers, LTO).
SANITIZE ?=
ifneq ($(SANITIZE),)
comma := ,
BUILD_DIR := build/sanitize
SANITIZE_FLAGS := -fsanitize=$(SANITIZE) -fno-sanitize-recover=all \
                  -fno-omit-frame-pointer -funwind-tables -O1
CFLAGS := $(filter-out -Ofast -fomit-frame-pointer -fno-asynchronous-unwind-tables \
            -D_FORTIFY_SOURCE=3 -flto=% -fuse-linker-plugin,$(CFLAGS)) $(SANITIZE_FLAGS)
SANITIZE_LD_DROP := -Wl$(comma)-Ofast -flto=% -fuse-linker-plugin
COMMON_LDFLAGS := $(filter-out $(SANITIZE_LD_DROP),$(COMMON_LDFLAGS)) \
                  -fsanitize=$(SANITIZE)
endif

# Define targets and source files
TARGET := ssh-chatter
SHARED_TARGET := libssh_chatter_backend.so
SRC := $(filter-out $(EXCLUDED_SRC),\
       $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/stubs/*.c) $(wildcard $(SRC_DIR)/utils/*.c))
SRC += $(INIH_DIR)/ini.c
OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRC))
SHARED_SRC := src/translator.c src/translation_helpers.c src/ssh_chatter_backend.c src/memory_manager.c
SHARED_OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SHARED_SRC))
DEP := $(OBJ:.o=.d) $(SHARED_OBJ:.o=.d)

STRESS_TARGET := stress-test
STRESS_SRC := tests/stress_main.c
STRESS_OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(STRESS_SRC))

DISPLAY_TEST_TARGET := display-model-test
ifneq ($(SANITIZE),)
DISPLAY_TEST_TARGET := $(BUILD_DIR)/display-model-test
endif
DISPLAY_TEST_SRC := tests/display_model_test.c src/display_model.c
DISPLAY_TEST_OBJ := $(patsubst %.c,$(BUILD_DIR)/%.o,$(DISPLAY_TEST_SRC))

# Unit tests: tests/unit/test_<name>.c linked against the sources listed in
# UNIT_DEPS_<name>. `make unit-test` builds and runs every one of them.
UNIT_TEST_NAMES := translation_helpers user_data security_layer chardet \
                   codepage jwt abstract_byte_buffer host_persistence \
                   ddial_protocol ddial_hub ansi_art
UNIT_TEST_BIN_DIR := $(BUILD_DIR)/unit
UNIT_TEST_BINS := $(addprefix $(UNIT_TEST_BIN_DIR)/test_,$(UNIT_TEST_NAMES))
UNIT_TEST_COMMON_SRC := src/memory_manager.c
UNIT_DEPS_translation_helpers := src/translation_helpers.c
UNIT_DEPS_user_data := src/user_data.c src/security_layer.c
UNIT_DEPS_security_layer := src/security_layer.c
UNIT_DEPS_chardet := src/utils/chardet.c
UNIT_DEPS_codepage := src/codepage.c
# test_jwt.c #includes jwt.c to reach its static base64url helpers.
UNIT_DEPS_jwt :=
UNIT_DEPS_abstract_byte_buffer :=
# Includes host_aggregate.c itself, so it links everything else but main.
UNIT_DEPS_host_persistence := $(filter-out src/host_aggregate.c src/main.c \
                                $(UNIT_TEST_COMMON_SRC),$(SRC))
UNIT_DEPS_ddial_hub := $(UNIT_DEPS_host_persistence)
# test_ddial_protocol.c #includes protocol.c (it is part of the aggregate).
UNIT_DEPS_ddial_protocol :=
# test_ansi_art.c #includes ansi_art.c (it is part of the aggregate).
UNIT_DEPS_ansi_art :=
DEP += $(patsubst %.c,$(BUILD_DIR)/%.d,$(wildcard tests/unit/*.c))
unit_test_objs = $(patsubst %.c,$(BUILD_DIR)/%.o,$(1))

.PHONY: all clean run stress-test display-model-test unit-test

# ==============================================================================
# BUILD RULES (Single Stage)
# ==============================================================================

# Default goal: Build the executable and shared library
all: $(TARGET) $(SHARED_TARGET)

$(DOORGAME_DIR)/libdoorgame.a:
	$(MAKE) -C $(DOORGAME_DIR) all

# Final linking for the executable
$(TARGET): $(OBJ) $(TTAK_LIB) $(DOORGAME_DIR)/libdoorgame.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Final linking for the shared library
$(SHARED_TARGET): $(SHARED_OBJ) $(TTAK_LIB) $(DOORGAME_DIR)/libdoorgame.a
	$(CC) $(CFLAGS) -shared -o $@ $^ $(COMMON_LDFLAGS)

$(STRESS_TARGET): $(filter-out $(BUILD_DIR)/src/main.o,$(OBJ)) $(STRESS_OBJ) $(TTAK_LIB)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(DISPLAY_TEST_TARGET): $(DISPLAY_TEST_OBJ) $(TTAK_LIB) | $(DOORGAME_DIR)/libdoorgame.a
	$(CC) $(CFLAGS) -o $@ $^ -Wno-error $(LDFLAGS)

.SECONDARY: $(patsubst %.c,$(BUILD_DIR)/%.o,$(wildcard tests/unit/*.c))
.SECONDEXPANSION:
$(UNIT_TEST_BIN_DIR)/test_%: $(BUILD_DIR)/tests/unit/test_%.o \
        $$(call unit_test_objs,$$(UNIT_DEPS_$$*) $(UNIT_TEST_COMMON_SRC)) \
        $(TTAK_LIB) | $(DOORGAME_DIR)/libdoorgame.a
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

unit-test: $(UNIT_TEST_BINS) $(DISPLAY_TEST_TARGET)
	@status=0; \
	for test_bin in $(UNIT_TEST_BINS) ./$(DISPLAY_TEST_TARGET); do \
		echo "== $$test_bin"; \
		$$test_bin || status=1; \
	done; \
	exit $$status

$(TTAK_LIB):
	$(MAKE) -C $(TTAK_DIR) all EXTRA_CFLAGS="$(CFLAGS_EXTRA)" EXTRA_LDFLAGS="$(LDFLAGS_EXTRA)"

# Rule for compiling object files
$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
# Cleanup only for LTO/standard build files
	rm -rf $(BUILD_DIR) $(TARGET) $(SHARED_TARGET) $(DEP) $(STRESS_OBJ) $(STRESS_TARGET) $(DISPLAY_TEST_TARGET)
	$(MAKE) -C $(DOORGAME_DIR) clean

# Include dependency files
-include $(DEP)

# Add Garbage Collector library if enabled
ifeq ($(ENABLE_GC),1)
COMMON_LDFLAGS += -lgc
endif
