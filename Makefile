# ----------------------------------
# NACmgr Makefile
# ----------------------------------

GPP = /usr/bin/g++ -g -Wno-deprecated -Wall -I include
LIB= -lstdc++ -lnsl -lcrypt -lpqxx -lpq -lsnmp -lpthread
INC= -I /usr/include/linux -I ../include

EXEC=NACpolling
POLL_OBJ= lib/snmpRec.o lib/fmt.o lib/getPass.o lib/pqDB.o lib/orDB.o lib/polling.o lib/poll_history.o

lib/NAC_tools.o: src/NAC_tools.cpp
        $(GPP) -c src/NAC_tools.cpp -o $@
lib/snmpRec.o: src/snmpRec.cpp
        $(GPP) -c src/snmpRec.cpp -o $@
lib/fmt.o: src/fmt.cpp
        $(GPP) -c src/fmt.cpp -o $@
lib/getPass.o: src/getPass.cpp
        $(GPP) -c src/getPass.cpp -o $@
lib/pqDB.o: src/pqDB.cpp
        $(GPP) -c src/pqDB.cpp -o $@
lib/poll_history.o: src/poll_history.cpp
        $(GPP) -c src/poll_history.cpp -o $@
lib/polling.o: src/polling.cpp
        $(GPP) -c src/polling.cpp -o $@
NACpolling: $(POLL_OBJ)  lib/polling.o
        $(GPP) $(INC) -o $@ $(POLL_OBJ) $(LIB)
        cp -f $@ /home/nacmgr/bin/$@
clean:
        rm -f lib/*.o  *.o $(EXEC) ;

