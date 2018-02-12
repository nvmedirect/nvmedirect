/*
 * NVMeDirect Userspace Tools
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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

#include <sys/ioctl.h>
#include "../include/nvmed.h"
#include "../include/lib_nvmed.h"

void usage(char* prog_name) {
	printf("usage : %s [dev_path] [get|set] [user] (number of queue)\n"
			      "%*s [dev_path] [del] [QID]\n",
			prog_name,
			(int)(8 + strlen(prog_name)), "");
}

int main(int argc, char** argv) {
	NVMED* nvmed;
	int result;
	struct passwd *user_ent;
	char* prog_name;
	char* dev_path;
	char* command;
	char* username;
	int num_queue;
	unsigned int max_queue, current_queue;
	int ret;

	prog_name = argv[0];
	if(argc < 4) {
		usage(prog_name);
		return -1;
	}

	dev_path = argv[1];
	command = argv[2];
	username = argv[3];

	nvmed = nvmed_open(dev_path, NVMED_NO_CACHE);

	if(nvmed == NULL) {
		printf("Can't access to device\n");
		return -1;
	}

	if(!strcmp(command, "get")) {
		user_ent = getpwnam(username);
		result = nvmed_get_user_quota(nvmed, user_ent->pw_uid, 
				&max_queue, &current_queue);

		if(result >= 0)
			printf("NVMeDirect - %s: %s => max:%u used:%u\n", 
					dev_path, username, max_queue, current_queue);
		else
			printf("Error on get user quota\n");
	}
	else if(!strcmp(command, "set") && argc == 5) {
		num_queue = atoi(argv[4]);
		user_ent = getpwnam(username);
		result = nvmed_set_user_quota(nvmed, user_ent->pw_uid, num_queue, 
				&max_queue, &current_queue);

		if(result >= 0)
			printf("NVMeDirect - %s: %s => max:%u used:%u\n", 
					dev_path, username, max_queue, current_queue);	
		else {
			if(result == -EPERM)
				printf("Permission denied (root privileges required)\n");
			else
				printf("Error on set user quota\n");
		}
	}
	else if(!strcmp(command, "del") && argc == 4) {
		num_queue = atoi(argv[3]);
		ret = ioctl(nvmed->ns_fd, NVMED_IOCTL_QUEUE_DELETE, &num_queue);

		if(ret == 0)
			printf("QID %d is destroyed\n", num_queue);
		else
			printf("Can't destroy QID %d\n", num_queue);
	}
	else {
		usage(prog_name);
	}

	nvmed_close(nvmed);


	return 0;
}
