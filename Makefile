CPPFLAGS := -D_FILE_OFFSET_BITS=64
CXXFLAGS := -std=c++11 $(CXXFLAGS)
LDFLAGS := $(LDFLAGS) -lassuan -lgcrypt
OBJ := blockdevice.o crypto.o header.o PBKDF2.o pinentry.o
PROGS := create format info
all: $(PROGS)
.SECONDARY:

%: %.cpp

%: %.o

%: %.o $(OBJ)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $*.o $(LDFLAGS) -o $@ $(OBJ)

.PHONY: clean
clean:
	$(RM) $(PROGS) *.o
