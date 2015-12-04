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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>

#include "file_util.h"

static int recurse(const char *path, mode_t mode,
		int (*fn)(const char *, mode_t, int))
{
	struct stat st;
	char dir[PATH_MAX];

	if (path == NULL)
		return -1;

	if (lstat(path, &st) == -1)
		return -1;

	if (strrchr(path, '/') != NULL) {
		int n = strlen(path)-strlen(strrchr(path, '/'));
		if (n >= PATH_MAX)
			return -1;

		strncpy(dir, path, n);
		dir[n] = '\0';
		fn(dir, mode, 1);
		return 0;
	}

	return -1;
}

int dlp_chmod(const char *path, mode_t mode, int recursive)
{
	int fd;
	struct stat lstat_info;
	struct stat fstat_info;
#ifdef HAVE_WIN32_PROC
	fprintf(stderr, "error: dlp_chmod not implemented on Win32 (%s)\n", path);
	return -1;
#else

	if (lstat(path, &lstat_info) == -1)
		return -1;

	fd = open(path, O_WRONLY, S_IRWXU);
	if (fd == -1)
		return -1;

	if (fstat(fd, &fstat_info) == -1) {
		close(fd);
		return -1;
	}

	/* this complex check is required because of 'chmod' security issue. */
	/* otherwise hacker can change other file's permission by using race condition and symbolic link. */
	if (lstat_info.st_mode == fstat_info.st_mode
			&& lstat_info.st_ino == fstat_info.st_ino
			&& lstat_info.st_dev == fstat_info.st_dev) {
		if (fchmod(fd, mode) == -1) {
			close(fd);
			return -1;
		}
	}

	close(fd);

	if (recursive)
		return recurse(path, mode, dlp_chmod);

	return 0;
#endif
}
