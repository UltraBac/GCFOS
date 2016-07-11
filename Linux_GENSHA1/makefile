CC=gcc
CFLAGS=-I.
LINKER_FLAGS=-lstdc++ -lpthread 

DEPS = LinuxTypes.h GCFOS_Include.h Misc.h
OBJ = Misc.o GenSha1.o 

%.o: %.cpp $(DEPS)
	$(CC) -g -std=c++0x -c -o $@ $< $(CFLAGS)

GenSha1: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LINKER_FLAGS)

clean:
	rm -f *.o
