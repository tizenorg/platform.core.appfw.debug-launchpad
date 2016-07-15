/*
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <bundle.h>
#include <bundle_internal.h>
#ifdef _APPFW_FEATURE_SOCKET_ACTIVATION
#include <systemd/sd-daemon.h>
#endif /* _APPFW_FEATURE_SOCKET_ACTIVATION */

#include "common.h"
#include "debug_util.h"
#include "defs.h"

#define MAX_PATH_LEN 1024
#define MAX_CMD_BUFSZ 1024
#define PATH_TMP "/tmp"
#define PATH_DATA "/data"
#define AUL_PKT_HEADER_SIZE (sizeof(int) + sizeof(int) + sizeof(int))

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

static int __create_server_socket(bool is_app)
{
	struct sockaddr_un saddr;
	int fd;
	int ret;

	if (is_app)
		fd = socket(AF_UNIX, SOCK_STREAM, 0);
	else
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

	if (is_app) {
		snprintf(saddr.sun_path, sizeof(saddr.sun_path),
				"%s/apps/%d/%d",
				SOCKET_PATH, getuid(), getpid());
		ret = mkdir(saddr.sun_path, 0700);
		if (ret != 0) {
			if (errno == EEXIST) {
				if (access(saddr.sun_path, R_OK) != 0) {
					_E("Failed to access %s directory - %d",
							saddr.sun_path, errno);
					close(fd);
					return -1;
				}
			} else {
				_E("Failed to create %s directory - %d",
						saddr.sun_path, errno);
				close(fd);
				return -1;
			}
		}
		snprintf(saddr.sun_path, sizeof(saddr.sun_path),
				"%s/apps/%d/%d/.app-sock",
				SOCKET_PATH, getuid(), getpid());
	} else {
		snprintf(saddr.sun_path, sizeof(saddr.sun_path),
				"%s/daemons/%d/.debug-launchpad-sock",
				SOCKET_PATH, getuid());
	}
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
		fd = __create_server_socket(false);
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
	int opt;

	sun_size = sizeof(struct sockaddr_un);

	*clifd = accept(fd, (struct sockaddr *)&aul_addr,
			(socklen_t *)&sun_size);
	if (*clifd == -1) {
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
	memcpy(&opt, buf + sizeof(int) + sizeof(int), sizeof(int));

	/* allocate for a null byte */
	pkt = (app_pkt_t *)calloc(1, AUL_PKT_HEADER_SIZE + datalen + 1);
	if (pkt == NULL) {
		close(*clifd);
		return NULL;
	}
	pkt->cmd = cmd;
	pkt->len = datalen;
	pkt->opt = opt;

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
	ptr = bundle_get_val(kb, AUL_K_COMP_TYPE);
	if (ptr)
		appinfo->comp_type = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_PKGID);
	if (ptr)
		appinfo->pkgid = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_EXEC);
	if (ptr)
		appinfo->app_path = strdup(ptr);
	if (appinfo->app_path)
		appinfo->original_app_path = strdup(appinfo->app_path);

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
	if (appinfo->comp_type)
		free(appinfo->comp_type);
	if (appinfo->pkgid)
		free(appinfo->pkgid);

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
		case 2: /* escape start */
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
		case 4: /* character escape */
			if (arg[i] == '\0')
				state = 6;
			else {
				*out = arg[i];
				out++;
				out_size--;
				state = 1;
			}
			break;
		case 5: /* token */
			if (out != start_out) {
				*out = '\0';
				out_size--;
				return i;
			}
			i--;
			state = 1;
			break;
		case 6:
			return -1;  /* error */
		case 7: /* terminate */
			*out = '\0';
			out_size--;
			return 0;
		default:
			state = 6;
			break;  /* error */
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
	bundle_del(kb, AUL_K_COMP_TYPE);

	/* Parse app_path to retrieve default bundle */
	if (cmd == PAD_CMD_LAUNCH) {
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

				flag = __parse_app_path(ptr, value,
						sizeof(value));
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

static char *__get_libdir(const char *path)
{
	char *path_dup;
	char buf[PATH_MAX];
	char *ptr;

	path_dup = strdup(path);
	if (path_dup == NULL)
		return NULL;

	ptr = strrchr(path_dup, '/');
	*ptr = '\0';

	snprintf(buf, sizeof(buf), "%s/../lib/", path_dup);
	free(path_dup);

	if (access(buf, F_OK) == -1)
		return NULL;

	return strdup(buf);
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
	}
}

void _set_env(appinfo_t *appinfo, bundle *kb)
{
	const char *str;
	const char **str_array = NULL;
	int len = 0;
	int i;
	char *libdir;

	setenv("PKG_NAME", appinfo->appid, 1);

	str = bundle_get_val(kb, AUL_K_STARTTIME);
	if (str)
		setenv("APP_START_TIME", str, 1);
	if (appinfo->hwacc)
		setenv("HWACC", appinfo->hwacc, 1);
	if (appinfo->taskmanage)
		setenv("TASKMANAGE", appinfo->taskmanage, 1);
	if (appinfo->appid)
		setenv("AUL_APPID", appinfo->appid, 1);
	if (appinfo->pkgid)
		setenv("AUL_PKGID", appinfo->pkgid, 1);

	str = bundle_get_val(kb, AUL_K_WAYLAND_DISPLAY);
	if (str)
		setenv("WAYLAND_DISPLAY", str, 1);

	str = bundle_get_val(kb, AUL_K_WAYLAND_WORKING_DIR);
	if (str)
		setenv("XDG_RUNTIME_DIR", str, 1);

	str = bundle_get_val(kb, AUL_K_API_VERSION);
	if (str)
		setenv("TIZEN_API_VERSION", str, 1);

	str = bundle_get_val(kb, AUL_K_ROOT_PATH);
	if (str)
		setenv("AUL_ROOT_PATH", str, 1);

	libdir = __get_libdir(appinfo->app_path);
	if (libdir) {
		setenv("LD_LIBRARY_PATH", libdir, 1);
		free(libdir);
	}

	if (bundle_get_type(kb, AUL_K_SDK) & BUNDLE_TYPE_ARRAY) {
		str_array = bundle_get_str_array(kb, AUL_K_SDK, &len);
	} else {
		str = bundle_get_val(kb, AUL_K_SDK);
		if (str) {
			str_array = &str;
			len = 1;
		}
	}

	for (i = 0; i < len; i++)
		__set_sdk_env(appinfo->appid, str_array[i]);
}

static char **__add_arg(bundle *kb, int *margc, const char *key)
{
	const char *str = NULL;
	const char **str_array = NULL;
	int len = 0;
	int i;
	char **new_argv = NULL;

	if (bundle_get_type(kb, key) & BUNDLE_TYPE_ARRAY) {
		str_array = bundle_get_str_array(kb, key, &len);
	} else {
		str = bundle_get_val(kb, key);
		if (str) {
			str_array = &str;
			len = 1;
		}
	}

	if (str_array) {
		if (strcmp(key, DLP_K_DEBUG_ARG) == 0
			|| strcmp(key, DLP_K_VALGRIND_ARG) == 0
			|| strcmp(key, DLP_K_ATTACH_ARG) == 0) {
			new_argv = (char **)calloc(1,
					sizeof(char *) * (len +	2));
			if (new_argv == NULL) {
				_E("Failed to allocate (key: %s)", key);
				return NULL;
			}

			/* need to add new_argv[0] */
			for (i = 0; i < len; i++)
				new_argv[1 + i] = strdup(str_array[i]);

			*margc = len + 1;
		}
	}

	return new_argv;
}

char **_create_argc_argv(bundle *kb, int *margc, const char *app_path)
{
	char **argv = NULL;
	char **new_argv = NULL;
	int argc;
	int i;
	char buf[PATH_MAX];
	const char *str;
	const char **str_array = NULL;
	int len = 0;
	const char *path;

	if (bundle_get_type(kb, AUL_K_SDK) & BUNDLE_TYPE_ARRAY) {
		str_array = bundle_get_str_array(kb, AUL_K_SDK, &len);
	} else {
		str = bundle_get_val(kb, AUL_K_SDK);
		if (str) {
			str_array = &str;
			len = 1;
		}
	}

	for (i = 0; i < len; i++) {
		if (str_array[i] == NULL)
			break;

		if (strcmp(str_array[i], SDK_DEBUG) == 0) {
			if (argv[0])
				free(argv[0]);
			snprintf(buf, sizeof(buf), "%s.exe", app_path);
			/* this code is added because core app don't have '.exe' excutable */
			/* if '.exe' not exist then use app_path */
			if (access(buf, F_OK) != 0)
				argv[0] = strdup(app_path);
			else
				argv[0] = strdup(buf);

			path = bundle_get_val(kb, DLP_K_GDBSERVER_PATH);
			if (path == NULL) {
				_E("Failed to get gdbserver path");
				*margc = 0;
				return NULL;
			}
			new_argv = __add_arg(kb, &argc, DLP_K_DEBUG_ARG);
			if (new_argv)
				new_argv[0] = strdup(path);
			argv = new_argv;
		} else if (strcmp(str_array[i], SDK_VALGRIND) == 0) {
			path = bundle_get_val(kb, DLP_K_VALGRIND_PATH);
			if (path == NULL) {
				_E("Failed to get valgrind path");
				*margc = 0;
				return NULL;
			}
			new_argv = __add_arg(kb, &argc, DLP_K_VALGRIND_ARG);
			if (new_argv)
				new_argv[0] = strdup(path);
			argv = new_argv;
		} else if (strcmp(str_array[i], SDK_ATTACH) == 0) {
			path = bundle_get_val(kb, DLP_K_GDBSERVER_PATH);
			if (path == NULL) {
				_E("Failed to get gdbserver path");
				*margc = 0;
				return NULL;
			}
			new_argv = __add_arg(kb, &argc, DLP_K_ATTACH_ARG);
			if (new_argv)
				new_argv[0] = strdup(path);
			argv = new_argv;
		}
	}

	if (argv == NULL) {
		argv = (char **)calloc(1, sizeof(char *) * 2);
		if (argv == NULL) {
			_E("out of memory");
			return NULL;
		}
		argv[0] = strdup(app_path);
		argc = 2;
	} else {
		argv[argc] = strdup(app_path);
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
	}

	buf[ret] = 0;
	close(fd);

	return ret;
}

int _proc_check_cmdline_bypid(int pid)
{
	char buf[MAX_CMD_BUFSZ];
	int ret;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0)
		return -1;

	_D("cmdline: %s", buf);

	return 0;
}

void _prepare_listen_sock(void)
{
	int fd;
	char buf[12];

	fd = __create_server_socket(true);
	if (fd < 0)
		return;

	snprintf(buf, sizeof(buf), "%d", fd);
	setenv("AUL_LISTEN_SOCK", buf, 1);
}

static int __delete_dir(const char *path)
{
	DIR *dp;
	struct dirent dentry;
	struct dirent *result = NULL;
	char buf[PATH_MAX];
	struct stat statbuf;
	int ret;

	if (path == NULL)
		return -1;

	dp = opendir(path);
	if (dp == NULL)
		return -1;

	while (readdir_r(dp, &dentry, &result) == 0 && result) {
		if (!strcmp(dentry.d_name, ".") || !strcmp(dentry.d_name, ".."))
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", path, dentry.d_name);
		ret = stat(buf, &statbuf);
		if (ret == 0) {
			if (S_ISDIR(statbuf.st_mode))
				__delete_dir(buf);
			else
				unlink(buf);
		}
	}

	rmdir(path);
	closedir(dp);

	return 0;
}

int _delete_sock_path(int pid, uid_t uid)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/run/aul/apps/%d/%d", uid, pid);
	if (access(path, F_OK) == 0)
		__delete_dir(path);

	if (access(path, F_OK) == 0)
		return -1;

	return 0;
}

int _close_all_fds(void)
{
	DIR *dp;
	struct dirent dentry;
	struct dirent *result = NULL;
	int fd;
	int max_fd;

	dp = opendir("/proc/self/fd");
	if (dp == NULL) {
		/* fallback */
		max_fd = sysconf(_SC_OPEN_MAX);
		for (fd = 3; fd < max_fd; fd++)
			close(fd);

		return 0;
	}

	while (readdir_r(dp, &dentry, &result) == 0 && result) {
		if (!isdigit(dentry.d_name[0]))
			continue;

		fd = atoi(dentry.d_name);
		if (fd < 3)
			continue;

		if (fd == dirfd(dp))
			continue;

		close(fd);
	}
	closedir(dp);

	return 0;
}

int _set_extra_data(const char *extra_data)
{
	int pipe[2];
	int r;
	ssize_t ret;
	ssize_t len;
	char buf[12];
	unsigned int datalen;

	if (extra_data == NULL) {
		_E("Invalid parameter");
		return -1;
	}

	_D("extra_data: %s", extra_data);

	r = pipe2(pipe, O_NONBLOCK);
	if (r != 0) {
		_E("Failed to create pipe");
		return -1;
	}

	datalen = strlen(extra_data);
	ret = write(pipe[1], &datalen, sizeof(datalen));
	if (ret < 0) {
		_E("Failed to write datalen");
		close(pipe[1]);
		close(pipe[0]);
		return -1;
	}

	len = 0;
	while (len < datalen) {
		ret = write(pipe[1], extra_data, datalen - len);
		if (ret < 0) {
			_E("Failed to write %s", extra_data);
			close(pipe[1]);
			close(pipe[0]);
			return -1;
		}
		len += ret;
	}
	close(pipe[1]);

	snprintf(buf, sizeof(buf), "%d", pipe[0]);
	setenv("AUL_EXTRA_DATA_FD", buf, 1);

	return 0;
}

