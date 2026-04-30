PRAIA_INCLUDE := $(shell praia --include-path)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
  OUT = plugins/l2.dylib
  LDFLAGS = -undefined dynamic_lookup
else
  OUT = plugins/l2-linux-$(shell uname -m).so
  LDFLAGS =
endif

all:
	g++ -std=c++17 -shared -fPIC -I$(PRAIA_INCLUDE) $(LDFLAGS) -o $(OUT) plugins/l2.cpp

clean:
	rm -f plugins/l2.dylib plugins/l2-linux-*.so

.PHONY: all clean
