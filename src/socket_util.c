/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/xattr.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <systemd/sd-daemon.h>

#include "common.h"
#include "socket_util.h"

static void __set_sock_option(int fd, int cli)
{
	int size;
	struct timeval tv = { 5, 200 * 1000 };  /*  5.2 sec */

	size = AUL_SOCK_MAXBUFF;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	if (cli)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static int __create_sock_activation(void)
{
	int listen_fds;

	listen_fds = sd_listen_fds(0);
	if (listen_fds == 1)
		return SD_LISTEN_FDS_START;
	else if (listen_fds > 1)
		_E("Too many file descriptors received.");
	else
		_E("There is no socket stream");

	return -1;
}

int create_server_sock(void)
{
	struct sockaddr_un saddr;
	int fd;

	fd = __create_sock_activation();
	if (fd < 0) {
		fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		/*  support above version 2.6.27*/
		if (fd < 0) {
			if (errno == EINVAL) {
				fd = socket(AF_UNIX, SOCK_STREAM, 0);
				if (fd < 0) {
					_E("second chance - socket create error");
					return -1;
				}
			} else {
				_E("socket error");
				return -1;
			}
		}
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sun_family = AF_UNIX;
	snprintf(saddr.sun_path, sizeof(saddr.sun_path),
			"%s/%d/.debug-launchpad-sock",
			SOCKET_PATH, getuid(), name);
	unlink(saddr.sun_path);

	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		_E("bind error");
		close(fd);
		return -1;
	}

	if (chmod(saddr.sun_path, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0) {
		/* Flawfinder: ignore*/
		_E("failed to change the socket permission");
		close(fd);
		return -1;
	}

	__set_sock_option(fd, 0);

	if (listen(fd, 128) == -1) {
		_E("listen error");
		close(fd);
		return -1;
	}

	return fd;
}

app_pkt_t *recv_pkt_raw(int fd, int *clifd, struct ucred *cr)
{
	int len;
	int ret;
	struct sockaddr_un aul_addr = { 0, };
	int sun_size;
	app_pkt_t *pkt = NULL;
	int cl = sizeof(struct ucred);
	unsigned char buf[AUL_SOCK_MAXBUFF];
	int cmd;
	int datalen;

	sun_size = sizeof(struct sockaddr_un);

	if ((*clifd = accept(fd, (struct sockaddr *)&aul_addr,
			(socklen_t *) &sun_size)) == -1) {
		if (errno != EINTR)
			_E("accept error");
		return NULL;
	}

	if (getsockopt(*clifd, SOL_SOCKET, SO_PEERCRED, cr,
			(socklen_t *) &cl) < 0) {
		_E("peer information error");
		close(*clifd);
		return NULL;
	}

	__set_sock_option(*clifd, 1);

retry_recv:
	/* receive header(cmd, datalen) */
	len = recv(*clifd, buf, AUL_PKT_HEADER_SIZE, 0);
	if (len < 0)
		if (errno == EINTR)
			goto retry_recv;

	if (len < AUL_PKT_HEADER_SIZE) {
		_E("recv error");
		close(*clifd);
		return NULL;
	}
	memcpy(&cmd, buf, sizeof(int));
	memcpy(&datalen, buf + sizeof(int), sizeof(int));

	/* allocate for a null byte */
	pkt = (app_pkt_t *)calloc(1, AUL_PKT_HEADER_SIZE + datalen + 1);
	if (pkt == NULL) {
		close(*clifd);
		return NULL;
	}
	pkt->cmd = cmd;
	pkt->len = datalen;

	len = 0;
	while ( len != pkt->len ) {
		ret = recv(*clifd, pkt->data + len, pkt->len - len, 0);
		if (ret < 0) {
			_E("recv error %d %d", len, pkt->len);
			free(pkt);
			close(*clifd);
			return NULL;
		}
		len += ret;
		_D("recv len %d %d", len, pkt->len);
	}

	return pkt;
}

int send_pkt_raw(int client_fd, app_pkt_t *pkt)
{
	int send_ret = 0;
	int pkt_size = 0;

	if (client_fd == -1 || pkt == NULL) {
		_E("arguments error!");
		goto error;
	}

	pkt_size = sizeof(pkt->cmd) + sizeof(pkt->len) + pkt->len;

	send_ret = send(client_fd, pkt, pkt_size, 0);
	_D("send(%d) : %d / %d", client_fd, send_ret, pkt_size);

	if (send_ret == -1) {
		_E("send error!");
		goto error;
	} else if (send_ret != pkt_size) {
		_E("send byte fail!");
		goto error;
	}

	return 0;

error:
	return -1;
}
