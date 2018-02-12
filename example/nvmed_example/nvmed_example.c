/*
 * NVMeDirect Userspace Application Example
 *
 * Copyright (c) 2016 Computer Systems Laboratory, Sungkyunkwan University.
 * http://csl.skku.edu
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../include/lib_nvmed.h"

int main(int argc, char** argv) {
	NVMED* nvmed;
	NVMED_QUEUE* queue;
	NVMED_HANDLE* handle;

	char* dev_path;

	void* ptr;

	if(argc != 2) {
		printf("usage: %s [dev_path]\n", argv[0]);
		return -1;
	}

	dev_path = argv[1];

	nvmed = nvmed_open(dev_path, 0);

	if(nvmed == NULL) {
		printf("%s: Cannot open the NVMe device %s\n", argv[0], dev_path);
		return -1;
	}
	
	queue = nvmed_queue_create(nvmed, 0);
	if(queue == NULL) {
		printf("Fail to create I/O queue\n");
		nvmed_close(nvmed);
		return -1;
	}
	
	handle = nvmed_handle_create(queue, HANDLE_SYNC_IO);
	if(handle == NULL) {
		printf("Fail to create I/O handle\n");
		nvmed_queue_destroy(queue);
		nvmed_close(nvmed);
		return -1;
	}

	ptr = nvmed_get_buffer(nvmed, 1);
	memset(ptr, 0x0, 4096);

	strcpy(ptr, "NVMeDirect I/O Test");
	nvmed_write(handle, ptr, 4096);

	memset(ptr, 0x0, 4096);
	nvmed_lseek(handle, 0, SEEK_SET);
	nvmed_read(handle, ptr, 4096);

	printf("%s\n", (char *)ptr);
	
	nvmed_put_buffer(ptr);

	nvmed_handle_destroy(handle);

	nvmed_queue_destroy(queue);

	nvmed_close(nvmed);


	return 0;
}
