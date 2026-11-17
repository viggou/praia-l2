PRAIA_INCLUDE := $(shell praia --include-path)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  OUT = plugins/l2.dylib
  LDFLAGS = -undefined dynamic_lookup
  # l2.cpp self-defines _XOPEN_SOURCE / _DARWIN_C_SOURCE before including
  # praia's fiber.h (which uses swapcontext(3) on macOS).
  EXTRA_FLAGS = -Wno-deprecated-declarations
else
  OUT = plugins/l2-linux-$(shell uname -m).so
  LDFLAGS =
  EXTRA_FLAGS =
endif

all:
	g++ -std=c++17 -shared -fPIC $(EXTRA_FLAGS) -I$(PRAIA_INCLUDE) $(LDFLAGS) -o $(OUT) plugins/l2.cpp

# Only this platform's build: the other prebuilt plugins are committed
clean:
	rm -f $(OUT)

.PHONY: all clean
