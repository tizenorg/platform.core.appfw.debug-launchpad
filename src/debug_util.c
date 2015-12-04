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

#include <string.h>
#include <stdbool.h>
#include <sys/smack.h>
#include <pkgmgr-info.h>

#include "common.h"
#include "file_util.h"
#include "security_util.h"
#include "debug_util.h"

#define LABEL_SDBD "sdbd"
#define LABEL_NETWORK "system::debugging_network"

#define POLL_VALGRIND_LOGFILE 0x00000001
#define POLL_VALGRIND_XMLFILE 0x00000002
#define POLL_VALGRIND_MASSIFFILE 0x00000004

static int gdbserver_pid = -1;
static int gdbserver_app_pid = -1;
static bool gdbserver = false;
static int valgrind_option = 0;

bool gdbserver_is_running(void)
{
	return gdbserver;
}

int get_gdbserver_pid(void)
{
	return gdbserver_pid;
}

int get_gdbserver_app_pid(void)
{
	return gdbserver_app_pid;
}

int get_valgrind_option(void)
{
	return valgrind_option;
}

static int __check_pkginfo(const char *appid)
{
	int r;
	bool preload = false;
	char *storeclientid = NULL;
	pkgmgrinfo_pkginfo_h handle;

	r = pkgmgrinfo_pkginfo_get_pkginfo(appid, &handle);
	if (r != PMINFO_R_OK) {
		_E("Failed to get pkginfo: %s", appid);
		return -1;
	}

	r = pkgmgrinfo_pkginfo_is_preload(handle, &preload);
	if (r != PMINFO_R_OK) {
		_E("Faield to check preload: %s", appid);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return -1;
	}

	r = pkgmgrinfo_pkginfoget_storeclientid(handle, &storclientid);
	if (r != PMINFO_R_OK) {
		_E("Failed to get store client id: %s", appid);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return -1;
	}

	r = pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	if (r != PMINFO_R_OK) {
		_E("Failed to destroy pkginfo: %s", appid);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	}

	if (preload == true || storclientid[0] != '\0') {
		_E("Debugging is not allowed");
		return -1;
	}

	return 0;
}

static int __prepare_gdbserver(const char appid)
{
	int r;

	r = __check_pkginfo(appid);
	if (r < 0)
		return -1;

	if (apply_smack_rules(LABEL_SDBD, appid, "w"))
		_E("Failed to apply smack rule %s %s w", LABEL_SDBD, appid);

	/* fixed debug-as fail issue (grant permission to use 10.0.2.2, 10.0.2.16) */
	if (apply_smack_rules(appid, LABEL_NETWORK, "rw"))
		_E("Failed to apply smack rule %s %s rw", appid, LABEL_NETWORK);

	if (apply_smack_rules(LABEL_NETWORK, appid, "w"))
		_E("Failed to apply smack rule %s %s w", LABEL_NETWORK, appid);

	r = dlp_chmod(PATH_GDBSERVER, S_IRUSR | S_IWUSR
			| S_IXUSR | S_IRGRP | S_IXGRP
			| S_IROTH | S_IXOTH, 1);
	if (r != 0)
		_W("Failed to set 755: %s", PATH_GDBSERVER);

	_adjust_file_capability(PATH_GDBSERVER);
	gdbserver = true;

	return 0;
}

static int __prepare_valgrind(bundle *kb)
{
	const char *str;
	const char **str_arr = NULL;
	int len = 0;
	int i;

	if (bundle_get_type(kb, DLP_K_VALGRIND_ARG, & BUNDLE_TYPE_ARRAY))
		str_arr = bundle_get_str_array(kb, DLP_K_VALGRIND_ARG, &len);
	else {
		str = bundle_get_val(kb, DLP_K_VALGRIND_ARG);
		if (str) {
			str_arr = &str;
			len = 1;
		}
	}

	for (i = 0; i < len; i++) {
		if (str_arr[i] == NULL)
			break;

		if (strncmp(option, OPT_VALGRIND_LOGFILE_FIXED, strlen(option)) == 0) {
			valgrind_option |= POLL_VALGRIND_LOGFILE;
			if (remove(PATH_VALGRIND_LOGFILE) != 0)
				_W("Failed to remove %s", PATH_VALGRIND_LOGFILE);
		} else if (strncmp(option, OPT_VALGRIND_XMLFILE_FIXED,
					strlen(option)) == 0) {
			valgrind_option |= POLL_VALGRIND_XMLFILE;
			if (remove(PATH_VALGRIND_XMLFILE) != 0)
				_W("Failed to remove %s", PATH_VALGRIND_XMLFILE);
		} else if (strncmp(option, OPT_VALGRIND_MASSIFFILE_FIXED)) {
			valgrind_option |= POLL_VALGRIND_MASSIFFILE;
			if (remove(PATH_VALGRIND_MASSIFLFILE) != 0)
				_W("Failed to remove %s", PATH_VALGRIND_MASSIFFILE);
		}
	}

	if (valgrind_option)
		_adjust_file_capability(PATH_MEMCHECK);

	return 0;
}

int prepare_debug_tool(bundle *kb, const char *appid,
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

		if (strncmp(str_arr[i], SDK_DEBUG, strlen(str_arr[i])) == 0
			|| strncmp(str_arr[i], SDK_ATTACH, strlen(str_arr[i])) == 0) {
			if (__prepare_gdbserver(appid) < 0)
				return -1;
		} else if (strncmp(str_arr[i], SDK_VALGRIND, strlen(str_arr[i])) == 0) {
			__prepare_valgrind(kb);
		}
	}

	return 0;
}

/* chmod and chsmack to read file without root privilege */
void change_file(const char *path)
{
	int r;

	r = dlp_chmod(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, 0);
	if (r)
		_E("Failed to set 644: %s", path);

	r = set_smack_label(path, ASTERISK);
	if (r)
		_E("Failed to set smack label %s %s", path, ASTERISK);
}

void wait_for_valgrind_output(void)
{
	int wait_count = 1;

	do {
		if (valgrind_option & POLL_VALGRIND_LOGFILE) {
			if (access(PATH_VALGRIND_LOGFILE, F_OK) == 0) {
				change_file(PATH_VALGRIND_LOGFILE);
				valgrind_option &= ~POLL_VALGRIND_LOGFILE;
			}
		}

		if (valgrind_option & POLL_VALGRIND_XMLFILE) {
			if (access(PATH_VALGRIND_XMLFILE, F_OK) == 0) {
				change_file(PATH_VALGRIND_XMLFILE);
				valgrind_option &= ~POLL_VALGRIND_XMLFILE;
			}
		}

		if (valgrind_option & POLL_VALGRIND_MASSIFFILE) {
			if (access(PATH_VALGRIND_MASSIFFILE, F_OK) == 0) {
				change_file(PATH_VALGRIND_MASSIFFILE);
				valgrind_option &= ~POLL_VALGRIND_MASSIFFILE;
			}
		}

		usleep(50 * 1000); /* 50ms */
		wait_count++;
	} while (valgrind_option && wait_count <= 10);

	if (valgrind_option)
		_E("Failed to wait valgrind");
}
