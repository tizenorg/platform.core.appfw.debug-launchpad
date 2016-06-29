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

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <bundle.h>
#include <bundle_internal.h>

#include "defs.h"
#include "common.h"
#include "debug_util.h"

#define POLL_VALGRIND_LOGFILE 0x00000001
#define POLL_VALGRIND_XMLFILE 0x00000002
#define POLL_VALGRIND_MASSIFFILE 0x00000004

static int gdbserver_pid = -1;
static int gdbserver_app_pid = -1;
static bool gdbserver;
static int valgrind_option;

bool _gdbserver_is_running(void)
{
	return gdbserver;
}

int _get_gdbserver_pid(void)
{
	return gdbserver_pid;
}

int _get_gdbserver_app_pid(void)
{
	return gdbserver_app_pid;
}

int _get_valgrind_option(void)
{
	return valgrind_option;
}

static int __prepare_gdbserver(bundle *kb, const char *appid)
{
	const char *path;

	path = bundle_get_val(kb, DLP_K_GDBSERVER_PATH);
	if (path == NULL)
		return -1;

	gdbserver = true;

	return 0;
}

static int __prepare_valgrind(bundle *kb)
{
	const char *str;
	const char **str_arr = NULL;
	int len = 0;
	int i;

	if (bundle_get_type(kb, DLP_K_VALGRIND_ARG) & BUNDLE_TYPE_ARRAY) {
		str_arr = bundle_get_str_array(kb, DLP_K_VALGRIND_ARG, &len);
		if (str_arr == NULL)
			return -1;
	} else {
		str = bundle_get_val(kb, DLP_K_VALGRIND_ARG);
		if (str) {
			str_arr = &str;
			len = 1;
		}
	}

	for (i = 0; i < len; i++) {
		if (str_arr[i] == NULL)
			break;

		if (strncmp(str_arr[i], OPT_VALGRIND_LOGFILE_FIXED,
				strlen(OPT_VALGRIND_LOGFILE_FIXED)) == 0) {
			valgrind_option |= POLL_VALGRIND_LOGFILE;
			if (access(PATH_VALGRIND_LOGFILE, F_OK) == 0) {
				if (remove(PATH_VALGRIND_LOGFILE) != 0)
					_W("Failed to remove %s",
						PATH_VALGRIND_LOGFILE);
			}
		} else if (strncmp(str_arr[i], OPT_VALGRIND_XMLFILE_FIXED,
				strlen(OPT_VALGRIND_XMLFILE_FIXED)) == 0) {
			valgrind_option |= POLL_VALGRIND_XMLFILE;
			if (access(PATH_VALGRIND_XMLFILE, F_OK) == 0) {
				if (remove(PATH_VALGRIND_XMLFILE) != 0)
					_W("Failed to remove %s",
						PATH_VALGRIND_XMLFILE);
			}
		} else if (strncmp(str_arr[i], OPT_VALGRIND_MASSIFFILE_FIXED,
				strlen(OPT_VALGRIND_MASSIFFILE_FIXED)) == 0) {
			valgrind_option |= POLL_VALGRIND_MASSIFFILE;
			if (access(PATH_VALGRIND_MASSIFFILE, F_OK) == 0) {
				if (remove(PATH_VALGRIND_MASSIFFILE) != 0)
					_W("Failed to remove %s",
						PATH_VALGRIND_MASSIFFILE);
			}
		}
	}

	return 0;
}

int _prepare_debug_tool(bundle *kb, const char *appid,
		const char **str_arr, int len)
{
	int i;

	if (appid == NULL || str_arr == NULL)
		return -1;

	gdbserver = false;
	gdbserver_pid = -1;
	gdbserver_app_pid = -1;
	valgrind_option = 0;

	for (i = 0; i < len; i++) {
		if (str_arr[i] == NULL)
			break;

		if (strncmp(str_arr[i], SDK_DEBUG, strlen(SDK_DEBUG)) == 0 ||
				strncmp(str_arr[i], SDK_ATTACH,
					strlen(SDK_ATTACH)) == 0) {
			if (__prepare_gdbserver(kb, appid) < 0)
				return -1;
		} else if (strncmp(str_arr[i], SDK_VALGRIND,
					strlen(SDK_VALGRIND)) == 0) {
			__prepare_valgrind(kb);
		}
	}

	return 0;
}

void _wait_for_valgrind_output(void)
{
	int wait_count = 1;

	do {
		if (valgrind_option & POLL_VALGRIND_LOGFILE) {
			if (access(PATH_VALGRIND_LOGFILE, F_OK) == 0)
				valgrind_option &= ~POLL_VALGRIND_LOGFILE;
		}

		if (valgrind_option & POLL_VALGRIND_XMLFILE) {
			if (access(PATH_VALGRIND_XMLFILE, F_OK) == 0)
				valgrind_option &= ~POLL_VALGRIND_XMLFILE;
		}

		if (valgrind_option & POLL_VALGRIND_MASSIFFILE) {
			if (access(PATH_VALGRIND_MASSIFFILE, F_OK) == 0)
				valgrind_option &= ~POLL_VALGRIND_MASSIFFILE;
		}

		usleep(50 * 1000); /* 50ms */
		wait_count++;
	} while (valgrind_option && wait_count <= 10);

	if (valgrind_option)
		_E("Failed to wait for valgrind output file");
}
