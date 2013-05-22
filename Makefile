CXXFLAGS := -std=c++11 $(CXXFLAGS) $(shell pkg-config --cflags libcrypto)
LDFLAGS := $(LDFLAGS) $(shell pkg-config --libs libcrypto)

all: format

format: format.o openssl-hash.o PBKDF2.o
	$(CXX) $(CXXFLAGS) format.o $(LDFLAGS) -o format openssl-hash.o PBKDF2.o

.PHONY: clean
clean:
	$(RM) format *.o
