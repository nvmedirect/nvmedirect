CC := gcc

LIBRARY_PATH := ../library

CFLAGS := -Wall -fPIC
LDFLAGS := -pthread -L$(LIBRARY_PATH) -lnvmed

NVMED_ADMIN = nvmed_admin
NVMED_ADMIN_OBJS = nvmed_admin.o

default: $(NVMED_ADMIN)

$(NVMED_ADMIN): $(NVMED_ADMIN_OBJS)
	$(CC) $(CFLAGS) $(NVMED_ADMIN_OBJS) -o $(NVMED_ADMIN) $(LDFLAGS) 

install: $(NVMED_ADMIN)
	install -m 755 -o root -g root $(NVMED_ADMIN) /usr/local/bin/

clean:
	rm -f $(NVMED_ADMIN) *.o

clobber: clean

.PHONY: default clean clobber
