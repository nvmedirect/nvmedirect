#
# FIO I/O engine for NVMeDirect
#
# Copyright (c) 2016 Computer Systems Laboratory, Sungkyunkwan University.
# http://csl.skku.edu
#
# This program is free software; you can redistribute it and/or modify it
# under the therm and condotions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#

CC := gcc

FIO_DIR := /usr/src/fio-2.17

LIBRARY_PATH := ../../library
CFLAGS := -Wall -fPIC
LDFLAGS := -pthread -L$(LIBRARY_PATH) -lnvmed

TARGETS = nvmed_fio

OBJS = $(addsuffix .o, $(TARGETS))

CFLAGS += -D_GNU_SOURCE -I$(FIO_DIR)
LDFLAGS += -shared #-rdynamic

all: $(OBJS) $(TARGETS)

nvmed_fio.o:

nvmed_fio:
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGETS) $(LDFLAGS) 

clean:
	$(RM) nvmed_fio *.o

.PHONY: all clean
