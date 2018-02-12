#
# FIO I/O engine for NVMeDirect
#
# Copyright (c) 2016 Computer Systems Laboratory, Sungkyunkwan University.
# http://csl.skku.edu
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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
