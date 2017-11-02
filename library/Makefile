CC := gcc

CFLAGS := -Wall -fPIC
LDFLAGS := -pthread -shared

SHARED_LIB = libnvmed.so
SHARED_OBJS = lib_nvmed.o utils/radix-tree.o 

INSTALL_HEADERS = ../include/nvme_hdr.h ../include/nvmed.h ../include/lib_nvmed.h ../include/radix-tree.h

default: $(SHARED_LIB)

$(SHARED_LIB): $(SHARED_OBJS)
	$(CC) $(CFLAGS) $(SHARED_OBJS) -o $(SHARED_LIB) $(LDFLAGS)

install: $(SHARED_LIB)
	install -m 644 -o root -g root $(INSTALL_HEADERS) /usr/local/include/
	install -m 644 -o root -g root $(SHARED_LIB) /usr/local/lib
	ldconfig 

clean:
	rm -f $(ALL_PROGS) $(SHARED_LIB) $(SHARED_OBJS)

clobber: clean

.PHONY: default clean clobber
