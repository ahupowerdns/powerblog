CXXFLAGS:=-std=gnu++17 -Wall -O2 -MMD -MP -ggdb -Iext/ -pthread  -I/usr/local/include/ -Wno-reorder -Iext/simplesocket
CFLAGS:= -Wall -O2 -MMD -MP -ggdb 

PROGRAMS = powerblog h2o-simple h2o-real

all: $(PROGRAMS)

clean:
	rm -f *~ *.o *.d test $(PROGRAMS)

-include *.d


powerblog: powerblog.o h2o-pp.o ext/simplesocket/comboaddress.o
	g++ -std=gnu++17 $^ -o $@ -pthread -lh2o-evloop -lsqlite3 -lssl -lcrypto -lz

h2o-simple: h2o-simple.o h2o-pp.o ext/simplesocket/comboaddress.o
	g++ -std=gnu++17 $^ -o $@ -pthread -lh2o-evloop -lssl -lcrypto -lz

h2o-real: h2o-real.o h2o-pp.o ext/simplesocket/comboaddress.o
	g++ -std=gnu++17 $^ -o $@ -pthread -lh2o-evloop -lssl -lcrypto -lz
