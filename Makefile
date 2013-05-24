CXXFLAGS := -std=c++11 $(CXXFLAGS)
LDFLAGS := $(LDFLAGS) -lassuan -lgcrypt
OBJ := crypto.o header.o PBKDF2.o pinentry.o
PROGS := format create
all: $(PROGS)
.SECONDARY:

%: %.cpp

%: %.o

%: %.o $(OBJ)
	$(CXX) $(CXXFLAGS) $*.o $(LDFLAGS) -o $@ $(OBJ)

.PHONY: clean
clean:
	$(RM) $(PROGS) *.o
