PRAIA_INCLUDE := $(shell praia --include-path)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  EXT = .dylib
  LDFLAGS = -undefined dynamic_lookup
else
  EXT = .so
  LDFLAGS =
endif

all:
	g++ -std=c++17 -shared -fPIC -I$(PRAIA_INCLUDE) $(LDFLAGS) -o plugins/l2$(EXT) plugins/l2.cpp

clean:
	rm -f plugins/l2.dylib plugins/l2.so

.PHONY: all clean
