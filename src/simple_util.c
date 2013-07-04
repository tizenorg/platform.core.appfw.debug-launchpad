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


#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include "simple_util.h"

#define BINSH_NAME	"/bin/sh"
#define BINSH_SIZE	7

#define PROC_STAT_GID_POS	5


static inline int __read_proc(const char *path, char *buf, int size);
static inline int __find_pid_by_cmdline(const char *dname,
				      const char *cmdline, void *priv);
static inline int __get_pgid_from_stat(int pid);


static inline int __read_proc(const char *path, char *buf, int size)
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

static inline int __find_pid_by_cmdline(const char *dname,
				      const char *cmdline, void *priv)
{
	char *apppath;
	int pid = 0;

	apppath = (char *)priv;
	if (strncmp(cmdline, apppath, MAX_LOCAL_BUFSZ-1) == 0) {
		pid = atoi(dname);
		if (pid != getpgid(pid))
			pid = 0;
	}

	return pid;
}

int __proc_iter_cmdline(
	int (*iterfunc)(const char *dname, const char *cmdline, void *priv),
		    void *priv)
{
	DIR *dp;
	struct dirent *dentry;
	int pid;
	int ret;
	char buf[MAX_LOCAL_BUFSZ];

	dp = opendir("/proc");
	if (dp == NULL) {
		return -1;
	}

	if (iterfunc == NULL)
		iterfunc = __find_pid_by_cmdline;

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		snprintf(buf, sizeof(buf), "/proc/%s/cmdline", dentry->d_name);
		ret = __read_proc(buf, buf, sizeof(buf));
		if (ret <= 0)
			continue;

		/* support app launched by shell script*/
		if (strncmp(buf, BINSH_NAME, BINSH_SIZE) == 0)
			pid =
			    iterfunc(dentry->d_name, &buf[BINSH_SIZE + 1],
				     priv);
		else
			pid = iterfunc(dentry->d_name, buf, priv);

		if (pid > 0) {
			closedir(dp);
			return pid;
		}
	}

	closedir(dp);
	return -1;
}

char *__proc_get_cmdline_bypid(int pid)
{
	char buf[MAX_LOCAL_BUFSZ];
	int ret;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0)
		return NULL;

	/* support app launched by shell script*/
	if (strncmp(buf, BINSH_NAME, BINSH_SIZE) == 0)
		return strdup(&buf[BINSH_SIZE + 1]);
	else
		return strdup(buf);
}

static inline int __get_pgid_from_stat(int pid)
{
	char buf[MAX_LOCAL_BUFSZ];
	char *str;
	int ret;
	int i;
	int count = 0;

	if (pid <= 1)
		return -1;

	snprintf(buf, sizeof(buf), "/proc/%d/stat", pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret < 0)
		return -1;

	for (i = 0; i < (ret - 1); i++) {
		if (buf[i] == ' ') {
			count++;
			if (count == PROC_STAT_GID_POS - 1)
				str = &(buf[i + 1]);
			else if (count == PROC_STAT_GID_POS) {
				buf[i] = 0;
				break;
			}
		}
	}

	if (count == PROC_STAT_GID_POS)
		pid = atoi(str);
	else
		pid = -1;

	return pid;
}

int __proc_iter_pgid(int pgid, int (*iterfunc) (int pid, void *priv),
		     void *priv)
{
	DIR *dp;
	struct dirent *dentry;
	int _pgid;
	int ret = -1;

	dp = opendir("/proc");
	if (dp == NULL) {
		return -1;
	}

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		_pgid = __get_pgid_from_stat(atoi(dentry->d_name));
		if (pgid == _pgid) {
			ret = iterfunc(atoi(dentry->d_name), priv);
			if (ret >= 0)
				break;
		}
	}

	closedir(dp);
	return ret;
}

