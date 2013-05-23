CXXFLAGS := -std=c++11 $(CXXFLAGS) $(shell pkg-config --cflags libcrypto)
LDFLAGS := $(LDFLAGS) $(shell pkg-config --libs libcrypto)
OBJ := openssl-hash.o PBKDF2.o
PROGS := format create
all: $(PROGS)
.SECONDARY:

%: %.o $(OBJ)
	$(CXX) $(CXXFLAGS) $*.o $(LDFLAGS) -o $@ $(OBJ)

.PHONY: clean
clean:
	$(RM) $(PROGS) *.o
