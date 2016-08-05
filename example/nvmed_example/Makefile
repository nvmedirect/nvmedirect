CC := gcc

LIBRARY_PATH := ../../library

CFLAGS := -Wall -fPIC
LDFLAGS := -pthread -L$(LIBRARY_PATH) -lnvmed

NVMED_EXAMPLE = nvmed_example
NVMED_EXAMPLE_OBJS = nvmed_example.o

default: $(NVMED_EXAMPLE)

$(NVMED_EXAMPLE): $(NVMED_EXAMPLE_OBJS)
	$(CC) $(CFLAGS) $(NVMED_EXAMPLE_OBJS) -o $(NVMED_EXAMPLE) $(LDFLAGS) 

clean:
	rm -f $(NVMED_EXAMPLE) *.o

.PHONY: default clean 
