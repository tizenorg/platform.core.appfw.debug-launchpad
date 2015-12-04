/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __SOCKET_UTIL_H__
#define __SOCKET_UTIL_H__

#define _GNU_SOURCE

#include <unistd.h>
#include <ctype.h>
#include <sys/socket.h>

#define SOCKET_PATH "/run/user"
#define MAX_LOCAL_BUFSZ 128
#define AUL_SOCK_MAXBUFF 65535

typedef struct _app_pkt_t {
	int cmd;
	int len;
	unsigned char data[1];
} app_pkt_t;

int create_server_sock(void);
app_pkt_t *recv_pkt_raw(int fd, int *clifd, struct ucred *cr);
int send_pkt_raw(int client_fd, app_pkt_t *pkt);

#endif /* __SOCKET_UTIL_H__ */
