/*
 *  debug-launchpad
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jungmin Cho <chivalry.cho@samsung.com>, Gwangho Hwang <gwang.hwang@samsung.com>
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
 *
 */


#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/smack.h>
#include <errno.h>
#include <fcntl.h>

#include "app_sock.h"
#include "simple_util.h"

static int __connect_client_sock(int sockfd, const struct sockaddr *saptr, socklen_t salen,
		   int nsec);


static inline void __set_sock_option(int fd, int cli)
{
	int size;
	struct timeval tv = { 3, 200 * 1000 };	/*  3.2 sec */

	size = AUL_SOCK_MAXBUFF;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	if (cli)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int __create_server_sock(int pid)
{
	struct sockaddr_un saddr;
	struct sockaddr_un p_saddr;
	int fd;
	mode_t orig_mask;

	/* Create basedir for our sockets */
	orig_mask = umask(0);
	(void) mkdir(AUL_SOCK_PREFIX, S_IRWXU | S_IRWXG | S_IRWXO | S_ISVTX);
	umask(orig_mask);

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

	memset(&saddr, 0, sizeof(saddr));
	saddr.sun_family = AF_UNIX;
	snprintf(saddr.sun_path, UNIX_PATH_MAX, "%s/%d", AUL_SOCK_PREFIX, pid);
	unlink(saddr.sun_path);

	/* labeling to socket for SMACK */
	if(getuid() == 0) {	// this is meaningful iff current user is ROOT
		if(smack_fsetlabel(fd, "@", SMACK_LABEL_IPOUT) != 0) {
			/* in case of unsupported filesystem on 'socket' */
			/* or permission error by using 'emulator', bypass*/
			if((errno != EOPNOTSUPP) && (errno != EPERM)) {
				_E("labeling to socket(IPOUT) error");
				close(fd);
				return -1;
			}
		}
		if(smack_fsetlabel(fd, "*", SMACK_LABEL_IPIN) != 0) {
			/* in case of unsupported filesystem on 'socket' */
			/* or permission error by using 'emulator', bypass*/
			if((errno != EOPNOTSUPP) && (errno != EPERM)) {
				_E("labeling to socket(IPIN) error");
				close(fd);
				return -1;
			}
		}
	}

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

	/* support app launched by shell script */
	/*if (pid != LAUNCHPAD_PID) {
		int pgid;
		pgid = getpgid(pid);
		if (pgid > 1) {
			snprintf(p_saddr.sun_path, UNIX_PATH_MAX, "%s/%d",
				 AUL_SOCK_PREFIX, pgid);
			if (link(saddr.sun_path, p_saddr.sun_path) < 0) {
				if (errno == EEXIST)
					_D("pg path - already exists");
				else
					_E("pg path - unknown create error");
			}
		}
	}*/

	return fd;
}

int __create_client_sock(int pid)
{
	int fd = -1;
	struct sockaddr_un saddr = { 0, };
	int retry = 1;
	int ret = -1;

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

	saddr.sun_family = AF_UNIX;
	snprintf(saddr.sun_path, UNIX_PATH_MAX, "%s/%d", AUL_SOCK_PREFIX, pid);
 retry_con:
	ret = __connect_client_sock(fd, (struct sockaddr *)&saddr, sizeof(saddr),
			100 * 1000);
	if (ret < -1) {
		_E("maybe peer not launched or peer daed\n");
		if (retry > 0) {
			usleep(100 * 1000);
			retry--;
			goto retry_con;
		}
	}
	if (ret < 0) {
		close(fd);
		return -1;
	}

	__set_sock_option(fd, 1);

	return fd;
}

static int __connect_client_sock(int fd, const struct sockaddr *saptr, socklen_t salen,
		   int nsec)
{
	int flags;
	int ret;
	int error;
	socklen_t len;
	fd_set readfds;
	fd_set writefds;
	struct timeval timeout;

	flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	error = 0;
	if ((ret = connect(fd, (struct sockaddr *)saptr, salen)) < 0) {
		if (errno != EAGAIN && errno != EINPROGRESS) {
			fcntl(fd, F_SETFL, flags);	
			return (-2);
		}
	}

	/* Do whatever we want while the connect is taking place. */
	if (ret == 0)
		goto done;	/* connect completed immediately */

	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	writefds = readfds;
	timeout.tv_sec = 0;
	timeout.tv_usec = nsec;

	if ((ret = select(fd + 1, &readfds, &writefds, NULL, 
			nsec ? &timeout : NULL)) == 0) {
		close(fd);	/* timeout */
		errno = ETIMEDOUT;
		return (-1);
	}

	if (FD_ISSET(fd, &readfds) || FD_ISSET(fd, &writefds)) {
		len = sizeof(error);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
			return (-1);	/* Solaris pending error */
	} else
		return (-1);	/* select error: sockfd not set*/

 done:
	(void) fcntl(fd, F_SETFL, flags);
	if (error) {
		close(fd);
		errno = error;
		return (-1);
	}
	return (0);
}

/**
 * @brief	Send data (in raw) to the process with 'pid' via socket
 */
int __app_send_raw(int pid, int cmd, unsigned char *kb_data, int datalen)
{
	int fd;
	int len;
	int ret;
	int res = 0;
	app_pkt_t *pkt = NULL;

	if (kb_data == NULL || datalen > AUL_SOCK_MAXBUFF - 8) {
		_E("keybundle error\n");
		return -EINVAL;
	}

	_D("pid(%d) : cmd(%d)", pid, cmd);

	fd = __create_client_sock(pid);
	if (fd < 0)
		return -ECOMM;

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return -ENOMEM;
	}
	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	pkt->cmd = cmd;
	pkt->len = datalen;
	memcpy(pkt->data, kb_data, datalen);

	if ((len = send(fd, pkt, datalen + 8, 0)) != datalen + 8) {
		_E("sendto() failed - %d %d (errno %d)", len, datalen + 8, errno);
		if(len > 0) {
			while (len != datalen + 8) {
				ret = send(fd, &pkt->data[len-8], datalen + 8 - len, 0);
				if (ret < 0) {
					_E("second sendto() failed - %d %d (errno %d)", ret, datalen + 8, errno);
					if (errno == EPIPE) {
						_E("pid:%d, fd:%d\n", pid, fd);
					}
					close(fd);
					if (pkt) {
						free(pkt);
						pkt = NULL;
					}
					return -ECOMM;
				}
				len += ret;
				_D("sendto() len - %d %d", len, datalen + 8);
			}
		} else {
			if (errno == EPIPE) {
				_E("pid:%d, fd:%d\n", pid, fd);
			}
			close(fd);
			if (pkt) {
				free(pkt);
				pkt = NULL;
			}
			return -ECOMM;
		}
	}
	if (pkt) {
		free(pkt);
		pkt = NULL;
	}

	len = recv(fd, &res, sizeof(int), 0);
	if (len == -1) {
		if (errno == EAGAIN) {
			_E("recv timeout \n");
			res = -EAGAIN;
		} else {
			_E("recv error\n");
			res = -ECOMM;
		}
	}
	close(fd);

	return res;
}

int __app_send_raw_with_noreply(int pid, int cmd, unsigned char *kb_data, int datalen)
{
	int fd;
	int len;
	int ret;
	int res = 0;
	app_pkt_t *pkt = NULL;

	if (kb_data == NULL || datalen > AUL_SOCK_MAXBUFF - 8) {
		_E("keybundle error\n");
		return -EINVAL;
	}

	_D("pid(%d) : cmd(%d)", pid, cmd);

	fd = __create_client_sock(pid);
	if (fd < 0)
		return -ECOMM;

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return -ENOMEM;
	}
	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	pkt->cmd = cmd;
	pkt->len = datalen;
	memcpy(pkt->data, kb_data, datalen);

	if ((len = send(fd, pkt, datalen + 8, 0)) != datalen + 8) {
		_E("sendto() failed - %d %d (errno %d)", len, datalen + 8, errno);
		if(len > 0) {
			while (len != datalen + 8) {
				ret = send(fd, &pkt->data[len-8], datalen + 8 - len, 0);
				if (ret < 0) {
					_E("second sendto() failed - %d %d (errno %d)", ret, datalen + 8, errno);
					if (errno == EPIPE) {
						_E("pid:%d, fd:%d\n", pid, fd);
					}
					close(fd);
					if (pkt) {
						free(pkt);
						pkt = NULL;
					}
					return -ECOMM;
				}
				len += ret;
				_D("sendto() len - %d %d", len, datalen + 8);
			}
		} else {
			if (errno == EPIPE) {
				_E("pid:%d, fd:%d\n", pid, fd);
			}
			close(fd);
			if (pkt) {
				free(pkt);
				pkt = NULL;
			}
			return -ECOMM;
		}
	}
	if (pkt) {
		free(pkt);
		pkt = NULL;
	}

	close(fd);

	return res;
}

app_pkt_t *__app_recv_raw(int fd, int *clifd, struct ucred *cr)
{
	int len;
	int ret;
	struct sockaddr_un aul_addr = { 0, };
	int sun_size;
	app_pkt_t *pkt = NULL;
	int cl = sizeof(struct ucred);

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

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if(pkt == NULL) {
		close(*clifd);
		return NULL;
	}
	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	__set_sock_option(*clifd, 1);

 retry_recv:
	/* receive single packet from socket */
	len = recv(*clifd, pkt, AUL_SOCK_MAXBUFF, 0);
	if (len < 0)
		if (errno == EINTR)
			goto retry_recv;

	if (len < 8) {
		_E("recv error %d %d", len, pkt->len);
		free(pkt);
		close(*clifd);
		return NULL;
	}

	while( len != (pkt->len + 8) ) {
		ret = recv(*clifd, &pkt->data[len-8], AUL_SOCK_MAXBUFF, 0);
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

app_pkt_t *__app_send_cmd_with_result(int pid, int cmd, unsigned char *kb_data, int datalen)
{
	int fd;
	int len;
	app_pkt_t *pkt = NULL;

	fd = __create_client_sock(pid);
	if (fd < 0)
		return NULL;

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return NULL;
	}
	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	pkt->cmd = cmd;
	pkt->len = datalen;
	if(kb_data) {
		memcpy(pkt->data, kb_data, datalen);
	}

	if ((len = send(fd, pkt, datalen + 8, 0)) != datalen + 8) {
		_E("sendto() failed - %d", len);
		if (errno == EPIPE) {
			_E("pid:%d, fd:%d\n", pid, fd);
		}
		close(fd);

		free(pkt);
		return NULL;
	}

retry_recv:
       /* receive single packet from socket */
	len = recv(fd, pkt, AUL_SOCK_MAXBUFF, 0);
	if (len == -1) {
		if (errno == EAGAIN) {
			_E("recv timeout \n");
			free(pkt);
			close(fd);
			return NULL;
		} else if (errno == EINTR) {
			goto retry_recv;
		} else {
			_E("recv error %s\n", strerror(errno));
			free(pkt);
			close(fd);
			return NULL;
		}
	} else
		_D("recv result  = %d", len);
	close(fd);

	return pkt;
}


