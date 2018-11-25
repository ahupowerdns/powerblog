CXXFLAGS:=-std=gnu++17 -Wall -O2 -MMD -MP -ggdb -Iext/ -pthread  -I/usr/local/include/ -Wno-reorder
CFLAGS:= -Wall -O2 -MMD -MP -ggdb 

PROGRAMS = powerblog

all: $(PROGRAMS)

clean:
	rm -f *~ *.o *.d test $(PROGRAMS)

-include *.d


powerblog: powerblog.o 
	g++ -std=gnu++17 $^ -o $@ -pthread -lh2o-evloop -lsqlite3 -lssl -lcrypto -lz

