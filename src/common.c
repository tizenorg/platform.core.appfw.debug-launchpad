/*
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: MooChang Kim <moochang.kim@samsung.com>
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <dirent.h>
#include <bundle.h>
#include <bundle_internal.h>
#ifdef _APPFW_FEATURE_SOCKET_ACTIVATION
#include <systemd/sd-daemon.h>
#endif /* _APPFW_FEATURE_SOCKET_ACTIVATION */

#include "common.h"
#include "debug_util.h"
#include "defs.h"

#define MAX_PATH_LEN 1024
#define BINSH_NAME "/bin/sh"
#define BINSH_SIZE 7
#define VALGRIND_NAME "/home/developer/sdk_tools/valgrind/usr/bin/valgrind"
#define VALGRIND_SIZE 51
#define BASH_NAME "/bin/bash"
#define BASH_SIZE 9
#define OPROFILE_NAME "/usr/bin/oprofile_command"
#define OPROFILE_SIZE 25
#define OPTION_VALGRIND_NAME "valgrind"
#define OPTION_VALGRIND_SIZE 8
#define MAX_CMD_BUFSZ 1024
#define PATH_TMP "/tmp"
#define PATH_DATA "/data"
#define AUL_PKT_HEADER_SIZE (sizeof(int) + sizeof(int))

static void __set_sock_option(int fd, int cli)
{
	int size;
	struct timeval tv = { 5, 200 * 1000 };  /* 5.2 sec */

	size = AUL_SOCK_MAXBUFF;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	if (cli)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

#ifdef _APPFW_FEATURE_SOCKET_ACTIVATION
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
#endif /* _APPFW_FEATURE_SOCKET_ACTIVATION */

static int __create_server_socket(void)
{
	struct sockaddr_un saddr;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	/* support above version 2.6.27 */
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
	snprintf(saddr.sun_path, sizeof(saddr.sun_path),
			"%s/%d/.debug-launchpad-sock",
			SOCKET_PATH, getuid());
	unlink(saddr.sun_path);

	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		_E("bind error");
		close(fd);
		return -1;
	}

	if (chmod(saddr.sun_path, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0) {
		/* Flawfinder: ignore */
		_E("Failed to change the socket permission");
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

int _create_server_sock(void)
{
	int fd = -1;

#ifdef _APPFW_FEATURE_SOCKET_ACTIVATION
	fd = __create_sock_activation();
#endif /* _APPFW_FEATURE_SOCKET_ACTIAVTION */
	if (fd < 0) {
		fd = __create_server_socket();
		if (fd < 0) {
			_E("server sock error %d", fd);
			return -1;
		}
	}

	return fd;
}

app_pkt_t *_recv_pkt_raw(int fd, int *clifd, struct ucred *cr)
{
	int len;
	int ret;
	struct sockaddr_un aul_addr = {0, };
	int sun_size;
	app_pkt_t *pkt = NULL;
	int cl = sizeof(struct ucred);
	unsigned char buf[AUL_SOCK_MAXBUFF];
	int cmd;
	int datalen;

	sun_size = sizeof(struct sockaddr_un);

	if ((*clifd = accept(fd, (struct sockaddr *)&aul_addr,
					(socklen_t *)&sun_size)) == -1) {
		if (errno != EINTR)
			_E("accept error");
		return NULL;
	}

	if (getsockopt(*clifd, SOL_SOCKET, SO_PEERCRED, cr,
				(socklen_t *)&cl) < 0) {
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
	while (len != pkt->len) {
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

int _send_pkt_raw(int client_fd, app_pkt_t *pkt)
{
	int send_ret = 0;
	int pkt_size = 0;

	if (client_fd == -1 || pkt == NULL) {
		_E("arguments error!");
		return -1;
	}

	pkt_size = sizeof(pkt->cmd) + sizeof(pkt->len) + pkt->len;

	send_ret = send(client_fd, pkt, pkt_size, 0);
	_D("send(%d) : %d / %d", client_fd, send_ret, pkt_size);

	if (send_ret == -1) {
		_E("send error!");
		return -1;
	} else if (send_ret != pkt_size) {
		_E("send byte fail!");
		return -1;
	}

	return 0;
}

static char *__appinfo_get_app_path(appinfo_t *appinfo)
{
	int i = 0;
	int path_len = -1;
	char *tmp_app_path;

	if (appinfo == NULL || appinfo->app_path == NULL)
		return NULL;

	while (appinfo->app_path[i] != 0) {
		if (appinfo->app_path[i] == ' '
				|| appinfo->app_path[i] == '\t') {
			path_len = i;
			break;
		}

		i++;
	}

	if (path_len == 0) {
		free(appinfo->app_path);
		appinfo->app_path = NULL;
	} else if (path_len > 0) {
		tmp_app_path = (char *)malloc(sizeof(char) * (path_len + 1));
		if (tmp_app_path == NULL)
			return NULL;

		snprintf(tmp_app_path, path_len + 1, "%s", appinfo->app_path);
		free(appinfo->app_path);
		appinfo->app_path = tmp_app_path;
	}

	return appinfo->app_path;
}

appinfo_t *_appinfo_create(bundle *kb)
{
	appinfo_t *appinfo;
	const char *ptr;

	appinfo = (appinfo_t *)calloc(1, sizeof(appinfo_t));
	if (appinfo == NULL)
		return NULL;

	ptr = bundle_get_val(kb, AUL_K_APPID);
	if (ptr)
		appinfo->appid = strdup(ptr);

	ptr = bundle_get_val(kb, AUL_K_PACKAGETYPE);
	if (ptr)
		appinfo->pkg_type = strdup(ptr);

	ptr = bundle_get_val(kb, AUL_K_HWACC);
	if (ptr)
		appinfo->hwacc = strdup(ptr);

	ptr = bundle_get_val(kb, AUL_K_PKGID);
	if (ptr)
		appinfo->debug_appid = strdup(ptr);

	ptr = bundle_get_val(kb, AUL_K_TASKMANAGE);
	if (ptr)
		appinfo->taskmanage = strdup(ptr);

	ptr = bundle_get_val(kb, AUL_K_EXEC);
	if (ptr) {
		appinfo->app_path = strdup(ptr);
		appinfo->original_app_path = strdup(ptr);
	}

	if (__appinfo_get_app_path(appinfo) == NULL) {
		_appinfo_free(appinfo);
		return NULL;
	}

	return appinfo;
}

void _appinfo_free(appinfo_t *appinfo)
{
	if (appinfo == NULL)
		return;

	if (appinfo->appid)
		free(appinfo->appid);

	if (appinfo->app_path)
		free(appinfo->app_path);

	if (appinfo->original_app_path)
		free(appinfo->original_app_path);

	if (appinfo->pkg_type)
		free(appinfo->pkg_type);

	if (appinfo->hwacc)
		free(appinfo->hwacc);

	if (appinfo->taskmanage)
		free(appinfo->taskmanage);

	if (appinfo->debug_appid)
		free(appinfo->debug_appid);

	free(appinfo);
}

static int __parse_app_path(const char *arg, char *out, int out_size)
{
	register int i;
	int state = 1;
	char *start_out = out;

	if (arg == NULL || out == NULL)
		return 0;

	for (i = 0; out_size > 1; i++) {
		switch (state) {
		case 1:
			switch (arg[i]) {
			case ' ':
			case '\t':
				state = 5;
				break;
			case '\0':
				state = 7;
				break;
			case '\"':
				state = 2;
				break;
			case '\\':
				state = 4;
				break;
			default:
				*out = arg[i];
				out++;
				out_size--;
				break;
			}
			break;
		case 2: /* escape start*/
			switch (arg[i]) {
			case '\0':
				state = 6;
				break;
			case '\"':
				state = 1;
				break;
			default:
				*out = arg[i];
				out++;
				out_size--;
				break;
			}
			break;
		case 4: /* character escape*/
			if (arg[i] == '\0')
				state = 6;
			else {
				*out = arg[i];
				out++;
				out_size--;
				state = 1;
			}
			break;
		case 5: /* token*/
			if (out != start_out) {
				*out = '\0';
				out_size--;
				return i;
			}
			i--;
			state = 1;
			break;
		case 6:
			return -1;  /* error*/
		case 7: /* terminate*/
			*out = '\0';
			out_size--;
			return 0;
		default:
			state = 6;
			break;  /* error*/
		}
	}

	if (out_size == 1)
		*out = '\0';

	/* Buffer overflow*/
	return -2;
}

void _modify_bundle(bundle *kb, int caller_pid, appinfo_t *appinfo, int cmd)
{
	char *ptr;
	char exe[MAX_PATH_LEN];
	int flag;
	char key[256];
	char value[256];

	bundle_del(kb, AUL_K_APPID);
	bundle_del(kb, AUL_K_EXEC);
	bundle_del(kb, AUL_K_PACKAGETYPE);
	bundle_del(kb, AUL_K_HWACC);
	bundle_del(kb, AUL_K_PKGID);
	bundle_del(kb, AUL_K_TASKMANAGE);

	if (cmd == APP_START || cmd == APP_START_RES
			|| cmd == APP_OPEN || cmd == APP_RESUME) {
		ptr = appinfo->original_app_path;
		flag = __parse_app_path(ptr, exe, sizeof(exe));
		if (flag > 0) {
			ptr += flag;
			SECURE_LOGD("parsing app_path: EXEC - %s", exe);

			do {
				flag = __parse_app_path(ptr, key, sizeof(key));
				if (flag <= 0)
					break;
				ptr += flag;

				flag = __parse_app_path(ptr, value, sizeof(value));
				if (flag < 0)
					break;
				ptr += flag;

				/* bundle_del(kb, key); */
				bundle_add(kb, key, value);
			} while (flag > 0);
		} else if (flag == 0) {
			_D("parsing app_path: No arguments");
		} else {
			_D("parsing app_path: Invalid argument");
		}

	}
}

static void __set_sdk_env(const char *appid, const char *value)
{
	char buf[MAX_LOCAL_BUFSZ];
	char *token = NULL;

	_D("key: %s / value: %s", AUL_K_SDK, value);
	/* http://gcc.gnu.org/onlinedocs/gcc/Cross_002dprofiling.html*/
	/* GCOV_PREFIX contains the prefix to add to the absolute paths */
	/*      in the object file. Prefix can be absolute, or relative.*/
	/*      The default is no prefix.  */
	/* GCOV_PREFIX_STRIP indicates the how many initial directory names */
	/*      to stripoff the hardwired absolute paths. Default value is 0. */
	if (strncmp(value, SDK_CODE_COVERAGE, strlen(value)) == 0) {
		token = strrchr(appid, '.');
		if (token == NULL)
			return;
		token++;

		snprintf(buf, sizeof(buf), PATH_TMP"/%s"PATH_DATA, token);
		setenv("GCOV_PREFIX", buf, 1);
		setenv("GCOV_PREFIX_STRIP", "0", 1);
	} else if (strncmp(value, SDK_DYNAMIC_ANALYSIS, strlen(value)) == 0) {
		setenv("LD_PRELOAD", PATH_DA_SO, 1);
	}
}

void _set_env(appinfo_t *appinfo, bundle *kb)
{
	const char *str;
	const char **str_array = NULL;
	int len = 0;
	int i;

	setenv("PKG_NAME", appinfo->appid, 1);

	str = bundle_get_val(kb, AUL_K_STARTTIME);
	if (str)
		setenv("APP_START_TIME", str, 1);
	if (appinfo->hwacc)
		setenv("HWACC", appinfo->hwacc, 1);
	if (appinfo->taskmanage)
		setenv("TASKMANAGE", appinfo->taskmanage, 1);

	if (bundle_get_type(kb, AUL_K_SDK) & BUNDLE_TYPE_ARRAY)
		str_array = bundle_get_str_array(kb, AUL_K_SDK, &len);
	else {
		str = bundle_get_val(kb, AUL_K_SDK);
		if (str) {
			str_array = &str;
			len = 1;
		}
	}

	for (i = 0; i < len; i++)
		__set_sdk_env(appinfo->appid, str_array[i]);
}

static char **__add_arg(bundle * kb, char **argv, int *margc, const char *key)
{
	const char *str = NULL;
	const char **str_array = NULL;
	int len = 0;
	int i;
	char **new_argv = NULL;

	if (bundle_get_type(kb, key) & BUNDLE_TYPE_ARRAY)
		str_array = bundle_get_str_array(kb, key, &len);
	else {
		str = bundle_get_val(kb, key);
		if (str) {
			str_array = &str;
			len = 1;
		}
	}

	if (str_array) {
		if (strncmp(key, DLP_K_DEBUG_ARG, strlen(key)) == 0
				|| strncmp(key, DLP_K_VALGRIND_ARG, strlen(key)) == 0) {
			new_argv = (char **)realloc(argv,
					sizeof(char *) * (*margc + len + 2));
			if (new_argv == NULL) {
				_E("Failed to realloc (key: %s)", key);
				exit(-1);
			}

			for (i = *margc + len + 1; i - (len + 1) >= 0; i--)
				new_argv[i] = new_argv[i - (len + 1)];

			/* need to add new_argv[0] */
			for (i = 0; i < len; i++)
				new_argv[1 + i] = strdup(str_array[i]);

			len++; /* gdbserver or valgrind */
		} else if (strncmp(key, DLP_K_ATTACH_ARG, strlen(key)) == 0) {
			new_argv = (char **)malloc((len + 2) * sizeof(char *));
			if (new_argv == NULL) {
				_E("Failed to malloc (key: %s)", key);
				exit(-1);
			}

			for (i = 0; i < len; i++)
				new_argv[1 + i] = strdup(str_array[i]);

			*margc = 0;
			len = len + 1;
		} else {
			new_argv = (char **)realloc(argv,
					sizeof(char *) * (*margc + len + 1));
			if (new_argv == NULL) {
				_E("Failed to realloc (key: %s)", key);
				exit(-1);
			}

			for (i = 0; i < len; i++)
				new_argv[*margc + i] = strdup(str_array[i]);
		}

		new_argv[*margc + len] = NULL;
		*margc += len;
	} else {
		if (strncmp(key, DLP_K_DEBUG_ARG, strlen(key)) == 0
				|| strncmp(key, DLP_K_VALGRIND_ARG, strlen(key)) == 0) {
			new_argv = (char **)realloc(argv,
					sizeof(char *) * (*margc + 2));
			if (new_argv == NULL) {
				_E("Failed to realloc (key: %s)", key);
				exit(-1);
			}

			for (i = *margc + 1; i - 1 >= 0; i--)
				new_argv[i] = new_argv[i - 1];

			/* need to add new_argv[0] */
			(*margc)++;
		}
	}

	if (new_argv == NULL)
		return argv;

	return new_argv;
}

char **_create_argc_argv(bundle *kb, int *margc, const char *app_path)
{
	char **argv = NULL;
	char **new_argv = NULL;
	int argc;
	int i;
	char buf[MAX_LOCAL_BUFSZ];
	const char *str;
	const char **str_array = NULL;
	int len = 0;

	argc = bundle_export_to_argv(kb, &argv);

	if (bundle_get_type(kb, AUL_K_SDK) & BUNDLE_TYPE_ARRAY)
		str_array = bundle_get_str_array(kb, AUL_K_SDK, &len);
	else {
		str = bundle_get_val(kb, AUL_K_SDK);
		if (str) {
			str_array = &str;
			len = 1;
		}
	}

	for (i = 0; i < len; i++) {
		if (str_array[i] == NULL)
			break;

		if (strncmp(str_array[i], SDK_DEBUG, strlen(str_array[i])) == 0) {
			if (argv[0])
				free(argv[0]);
			snprintf(buf, sizeof(buf), "%s.exe", app_path);
			/* this code is added because core app don't have '.exe' excutable */
			/* if '.exe' not exist then use app_path */
			if (access(buf, F_OK) != 0)
				argv[0] = strdup(app_path);
			else
				argv[0] = strdup(buf);

			new_argv = __add_arg(kb, argv, &argc, DLP_K_DEBUG_ARG);
			new_argv[0] = strdup(PATH_GDBSERVER);
			argv = new_argv;
		} else if (strncmp(str_array[i], SDK_VALGRIND, strlen(str_array[i])) == 0) {
			new_argv = __add_arg(kb, argv, &argc, DLP_K_VALGRIND_ARG);
			new_argv[0] = strdup(PATH_VALGRIND);
			argv = new_argv;
		} else if (strncmp(str_array[i], SDK_UNIT_TEST, strlen(str_array[i])) == 0) {
			new_argv = __add_arg(kb, argv, &argc, DLP_K_UNIT_TEST_ARG);
			argv = new_argv;
		} else if (strncmp(str_array[i], SDK_ATTACH, strlen(str_array[i])) == 0) {
			new_argv = __add_arg(kb, argv, &argc, DLP_K_ATTACH_ARG);
			new_argv[0] = strdup(PATH_GDBSERVER);
			argv = new_argv;
		}

	}

	*margc = argc;

	return argv;
}

static int __read_proc(const char *path, char *buf, int size)
{
	int fd;
	int ret;

	if (buf == NULL || path == NULL)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		close(fd);
		return -1;
	} else
		buf[ret] = 0;

	close(fd);

	return ret;
}

char *_proc_get_cmdline_bypid(int pid)
{
	char buf[MAX_CMD_BUFSZ];
	int ret;
	char* ptr = NULL;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0)
		return NULL;

	/* support app launched by shell script*/
	if (strncmp(buf, BINSH_NAME, BINSH_SIZE) == 0)
		return strdup(&buf[BINSH_SIZE + 1]);
	else if (strncmp(buf, VALGRIND_NAME, VALGRIND_SIZE) == 0) {
		/* buf comes with double null-terminated string */
		while (1) {
			while (*ptr)
				ptr++;
			ptr++;

			if (!(*ptr))
				break;

			/* ignore trailing "--" */
			if (strncmp(ptr, "-", 1) != 0)
				break;
		}

		return strdup(ptr);
	} else if (strncmp(buf, BASH_NAME, BASH_SIZE) == 0) {
		if (strncmp(&buf[BASH_SIZE + 1], OPROFILE_NAME, OPROFILE_SIZE) == 0) {
			if (strncmp(&buf[BASH_SIZE + OPROFILE_SIZE + 2],
						OPTION_VALGRIND_NAME, OPTION_VALGRIND_SIZE) == 0) {
				return strdup(&buf[BASH_SIZE + OPROFILE_SIZE +
						OPTION_VALGRIND_SIZE + 3]);
			}
		}
	}

	return strdup(buf);
}
