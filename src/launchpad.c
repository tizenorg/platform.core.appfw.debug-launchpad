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

/*
 * simple AUL daemon - launchpad 
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <X11/Xlib.h>
#include <sys/types.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/prctl.h>
#include <malloc.h>

#include "app_sock.h"
#include "aul.h"

#include "config.h"

#include "menu_db_util.h"
#include "simple_util.h"
#include "access_control.h"
#include "preload.h"
#include "preexec.h"
#include "perf.h"
#include "sigchild.h"
#include "aul_util.h"

#include "heap_dbg.h"

#include "gl.h"

#include <sqlite3.h>
#include <sys/smack.h>
#include "fileutils.h"
#include <sys/capability.h>

#define _static_ static inline
#define POLLFD_MAX 1
#define SQLITE_FLUSH_MAX	(1048576)	/* (1024*1024) */
#define AUL_POLL_CNT		15
#define AUL_PR_NAME			16
#define APPID_LEN	10
#define PATH_TMP "/tmp"
#define PATH_DATA "/data"

#define SDK_CODE_COVERAGE "CODE_COVERAGE"
#define SDK_DEBUG "DEBUG"
#define SDK_DYNAMIC_ANALYSIS "DYNAMIC_ANALYSIS"
#define SDK_UNIT_TEST "UNIT_TEST"
#define SDK_VALGRIND "VALGRIND"
#define SDK_LD_FLAG "LD_FLAG"

/* DLP is short for debug-launchpad */
#define DLP_K_DEBUG_ARG "__DLP_DEBUG_ARG__"
#define DLP_K_UNIT_TEST_ARG "__DLP_UNIT_TEST_ARG__"
#define DLP_K_VALGRIND_ARG "__DLP_VALGRIND_ARG__"
#define DLP_K_LD_FLAG "__DLP_LD_FLAG__"

#define PATH_GDBSERVER	"/home/developer/sdk_tools/gdbserver/gdbserver"
#define PATH_VALGRIND	"/home/developer/sdk_tools/valgrind/usr/bin/valgrind"
#define PATH_DA_SO	"/usr/lib/da_probe_tizen.so"
#define PATH_NATIVE_APP	"/opt/apps/"

#define OPT_VALGRIND_LOGFILE		"--log-file="
#define OPT_VALGRIND_LOGFILE_FIXED	"--log-file=/tmp/valgrind_result.txt"
#define PATH_VALGRIND_LOGFILE		"/tmp/valgrind_result.txt"
#define OPT_VALGRIND_XMLFILE		"--xml-file="
#define OPT_VALGRIND_XMLFILE_FIXED	"--xml-file=/tmp/valgrind_result.xml"
#define PATH_VALGRIND_XMLFILE		"/tmp/valgrind_result.xml"

#if (ARCH==arm)
#define PATH_MEMCHECK	"/opt/home/developer/sdk_tools/valgrind/usr/lib/valgrind/memcheck-arm-linux"
#elif (ARCH==x86)
#define PATH_MEMCHECK	"/opt/home/developer/sdk_tools/valgrind/usr/lib/valgrind/memcheck-x86-linux"
#endif

#define POLL_VALGRIND_LOGFILE		0x00000001
#define POLL_VALGRIND_XMLFILE		0x00000002

#define CAPABILITY_SET_ORIGINAL		0
#define CAPABILITY_SET_INHERITABLE	1

static int need_to_set_inh_cap_after_fork = 0;
static char *launchpad_cmdline;
static int initialized = 0;

static int poll_outputfile = 0;
static int is_gdbserver_launched;

void __set_oom();
void __set_env(app_info_from_db * menu_info, bundle * kb);
int __prepare_exec(const char *pkg_name,
			    const char *app_path, app_info_from_db * menu_info,
			    bundle * kb);
int __fake_launch_app(int cmd, int pid, bundle * kb);
char **__create_argc_argv(bundle * kb, int *margc, const char *app_path);
int __normal_fork_exec(int argc, char **argv);
void __real_launch(const char *app_path, bundle * kb);
static inline int __parser(const char *arg, char *out, int out_size);
void __modify_bundle(bundle * kb, int caller_pid,
			    app_info_from_db * menu_info, int cmd);
int __send_to_sigkill(int pid);
int __term_app(int pid);
void __real_send(int clifd, int ret);
void __send_result_to_caller(int clifd, int ret);
void __launchpad_main_loop(int main_fd);
int __launchpad_pre_init(int argc, char **argv);
int __launchpad_post_init();

extern ail_error_e ail_db_close(void);



void __set_oom()
{
	char buf[MAX_LOCAL_BUFSZ];
	FILE *fp;

	/* we should reset oomadj value as default because child 
	inherits from parent oom_adj*/
	snprintf(buf, MAX_LOCAL_BUFSZ, "/proc/%d/oom_adj", getpid());
	fp = fopen(buf, "w");
	if (fp == NULL)
		return;
	fprintf(fp, "%d", -16);
	fclose(fp);
}

void __set_sdk_env(app_info_from_db* menu_info, char* str, bundle * kb) {
	char buf_pkgname[MAX_LOCAL_BUFSZ];
	char buf[MAX_LOCAL_BUFSZ];
	int ret;

	_D("key : %s / value : %s", AUL_K_SDK, str);
	/* http://gcc.gnu.org/onlinedocs/gcc/Cross_002dprofiling.html*/
	/* GCOV_PREFIX contains the prefix to add to the absolute paths */
	/*	in the object file. Prefix can be absolute, or relative.*/
	/*	The default is no prefix.  */
	/* GCOV_PREFIX_STRIP indicates the how many initial directory names */
	/*	to stripoff the hardwired absolute paths. Default value is 0. */
	if (strncmp(str, SDK_CODE_COVERAGE, strlen(str)) == 0) {
		strncpy(buf_pkgname,_get_pkgname(menu_info),MAX_LOCAL_BUFSZ-1);
		buf_pkgname[MAX_LOCAL_BUFSZ-1]='\0';
		snprintf(buf, MAX_LOCAL_BUFSZ, PATH_TMP"/%s"PATH_DATA
			, strtok(buf_pkgname,"."));
		ret = setenv("GCOV_PREFIX", buf, 1);
		_D("GCOV_PREFIX : %d", ret);
		ret = setenv("GCOV_PREFIX_STRIP", "0", 1);
		_D("GCOV_PREFIX_STRIP : %d", ret);
	}
	else if (strncmp(str, SDK_DYNAMIC_ANALYSIS, strlen(str)) == 0)
	{
		ret = setenv("LD_PRELOAD", PATH_DA_SO, 1);
		_D("LD_PRELOAD : %d", ret);
	}
	else if (strncmp(str, SDK_LD_FLAG, strlen(str)) == 0)
	{
		const char *flag_str = NULL;
		const char **flag_str_array = NULL;
		int flag_len;
		if(bundle_get_type(kb, DLP_K_LD_FLAG) & BUNDLE_TYPE_ARRAY) {
			flag_str_array = bundle_get_str_array(kb, DLP_K_LD_FLAG, &flag_len);
		} else {
			flag_str = bundle_get_val(kb, DLP_K_LD_FLAG);
			if(flag_str) {
				flag_str_array = &flag_str;
				flag_len = 1;
			}
		}
		if(flag_str_array != NULL) {
			int i;
			char * f_name;
			char * f_value;
			for (i = 0; i < flag_len; i++) {
				strncpy(buf,flag_str_array[i],MAX_LOCAL_BUFSZ);
				f_name = strtok(buf,"=");
				f_value = strtok(NULL,"=");
				if(f_value) {
					ret = setenv(f_name,f_value,1);
					_D("LD_FLAG : %s %s %d",f_name,f_value,ret);
				} else {
					_E("LD_FLAG : Wrong option! %s", flag_str_array[i]);
				}
			}
		}

	}
}


void __set_env(app_info_from_db * menu_info, bundle * kb)
{
	const char *str;
	const char **str_array;
	int len;
	int i;

	setenv("PKG_NAME", _get_pkgname(menu_info), 1);

	USE_ENGINE("gl")

	str = bundle_get_val(kb, AUL_K_STARTTIME);
	if (str != NULL)
		setenv("APP_START_TIME", str, 1);

	if(bundle_get_type(kb, AUL_K_SDK) & BUNDLE_TYPE_ARRAY) {
		str_array = bundle_get_str_array(kb, AUL_K_SDK, &len);
		if(str_array != NULL) {
			for (i = 0; i < len; i++) {
				_D("index : [%d]", i);
				__set_sdk_env(menu_info, (char *)str_array[i], kb);
			}
		}
	} else {
		str = bundle_get_val(kb, AUL_K_SDK);
		if(str != NULL) {
			__set_sdk_env(menu_info, (char *)str, kb);
		}
	}
	if (menu_info->hwacc != NULL)
		setenv("HWACC", menu_info->hwacc, 1);
}

int __prepare_exec(const char *pkg_name,
			    const char *app_path, app_info_from_db * menu_info,
			    bundle * kb)
{
	char *file_name;
	char process_name[AUL_PR_NAME];
	int ret;

	/* Set new session ID & new process group ID*/
	/* In linux, child can set new session ID without check permission */
	/* TODO : should be add to check permission in the kernel*/
	setsid();

	__preexec_run(menu_info->pkg_type, pkg_name, app_path);

	/* SET OOM*/
	__set_oom();

	/* SET PRIVILEGES*/
	if(bundle_get_val(kb, AUL_K_PRIVACY_APPID) == NULL) {
		_D("pkg_name : %s / pkg_type : %s / app_path : %s ", pkg_name
			, menu_info->pkg_type, app_path);
		if ((ret = __set_access(pkg_name, menu_info->pkg_type
			, app_path)) < 0) 
		{
			 _D("fail to set privileges - check your package's credential : %d\n"
				, ret);
			return -1;
		}
	}
	/* SET DUMPABLE - for coredump*/
	prctl(PR_SET_DUMPABLE, 1);

	/* SET PROCESS NAME*/
	if (app_path == NULL) {
		_D("app_path should not be NULL - check menu db");
		return -1;
	}
	file_name = strrchr(app_path, '/') + 1;
	if (file_name == NULL) {
		_D("can't locate file name to execute");
		return -1;
	}
	memset(process_name, '\0', AUL_PR_NAME);
	snprintf(process_name, AUL_PR_NAME, "%s", file_name);
	prctl(PR_SET_NAME, process_name);

	/* SET ENVIROMENT*/
	__set_env(menu_info, kb);

	return 0;
}

int __fake_launch_app(int cmd, int pid, bundle * kb)
{
	int datalen;
	int ret;
	bundle_raw *kb_data;

	bundle_encode(kb, &kb_data, &datalen);
	if ((ret = __app_send_raw(pid, cmd, kb_data, datalen)) < 0)
		_E("error request fake launch - error code = %d", ret);
	free(kb_data);
	return ret;
}

char** __add_arg(bundle * kb, char **argv, int *margc, const char *key)
{
	const char *str = NULL;
	const char **str_array = NULL;
	int len = 0;
	int i;
	char ** new_argv = NULL;

	if(bundle_get_type(kb, key) & BUNDLE_TYPE_ARRAY) {
		str_array = bundle_get_str_array(kb, key, &len);
	} else {
		str = bundle_get_val(kb, key);
		if(str) {
			str_array = &str;
			len = 1;
		}
	}
	if(str_array != NULL) {
		if(strncmp(key, DLP_K_DEBUG_ARG, strlen(key)) == 0
			|| strncmp(key, DLP_K_VALGRIND_ARG, strlen(key)) == 0)
		{
			new_argv = (char **) realloc(argv
				, sizeof(char *) * (*margc+len+2));
			if(!new_argv) {
				_E("realloc fail (key = %s)", key);
				exit(-1);
			}
			for(i=*margc+len+1; i-(len+1)>=0; i--) {
				new_argv[i] = new_argv[i-(len+1)];
			}
			// need to add new_argv[0]
			for(i=0; i<len; i++) {
				new_argv[1+i] = strdup(str_array[i]);
			}
			len++;	/* gdbserver or valgrind */
			_D("uid : %d", getuid());
			_D("euid : %d", geteuid());
			_D("gid : %d", getgid());
			_D("egid : %d", getegid());
		} else {
			new_argv = (char **) realloc(argv
				, sizeof(char *) * (*margc+len+1));
			if(!new_argv) {
				_E("realloc fail (key = %s)", key);
				exit(-1);
			}
			for(i=0; i<len; i++) {
				new_argv[*margc+i] = strdup(str_array[i]);
			}
		}
		new_argv[*margc+len] = NULL;
		*margc += len;
	} else {
		if(strncmp(key, DLP_K_DEBUG_ARG, strlen(key)) == 0
			|| strncmp(key, DLP_K_VALGRIND_ARG, strlen(key)) == 0)
		{
			new_argv = (char **) realloc(argv
				, sizeof(char *) * (*margc+2));
			if(!new_argv) {
				_E("realloc fail (key = %s)", key);
				exit(-1);
			}
			for(i=*margc+1; i-1>=0; i--) {
				new_argv[i] = new_argv[i-1];
			}
			// need to add new_argv[0]
			(*margc)++;
		}
	}

	if(new_argv==NULL) return argv;
	return new_argv;
}

char **__create_argc_argv(bundle * kb, int *margc, const char *app_path)
{
	char **argv = NULL;
	char **new_argv = NULL;
	int argc;

	const char *str = NULL;
	const char **str_array = NULL;
	int len = 0;
	int i;

	argc = bundle_export_to_argv(kb, &argv);
	if (argv) {
		for(i=1; i<argc; i++) {
			argv[i] = strdup(argv[i]);
		}
		argv[0] = strdup(app_path);
	} else {
		_E("bundle_export_to_argv error");
		exit(-1);
	}

	if(bundle_get_type(kb, AUL_K_SDK) & BUNDLE_TYPE_ARRAY) {
		str_array = bundle_get_str_array(kb, AUL_K_SDK, &len);
	} else {
		str = bundle_get_val(kb, AUL_K_SDK);
		if(str) {
			str_array = &str;
			len = 1;
		}
	}
	if(str_array == NULL) {
		*margc = argc;
		return argv;
	}

	for (i = 0; i < len; i++) {
		if(str_array[i] == NULL) break;
		_D("index : [%d]", i);
		/* gdbserver */
		if (strncmp(str_array[i], SDK_DEBUG, strlen(str_array[i])) == 0)
		{
			char buf[MAX_LOCAL_BUFSZ];
			if (argv[0]) free(argv[0]);
			snprintf(buf,MAX_LOCAL_BUFSZ,"%s.exe",app_path);
			argv[0] = strdup(buf);
			new_argv = __add_arg(kb, argv, &argc, DLP_K_DEBUG_ARG);
			new_argv[0] = strdup(PATH_GDBSERVER);
			argv = new_argv;
		}
		/* valgrind */
		else if (strncmp(str_array[i], SDK_VALGRIND
			, strlen(str_array[i])) == 0)
		{
			new_argv = __add_arg(kb, argv, &argc
				, DLP_K_VALGRIND_ARG);
			new_argv[0] = strdup(PATH_VALGRIND);
			argv = new_argv;
		}
		/* unit test */
		else if (strncmp(str_array[i], SDK_UNIT_TEST
			, strlen(str_array[i])) == 0)
		{
			new_argv = __add_arg(kb, argv, &argc
				, DLP_K_UNIT_TEST_ARG);
			argv = new_argv;
		}
	}

	*margc = argc;
	if(new_argv==NULL) return argv;
	return new_argv;
}

int __normal_fork_exec(int argc, char **argv)
{
	_D("start real fork and exec\n");

	if (execv(argv[0], argv) < 0) {	/* Flawfinder: ignore */
		if (errno == EACCES) {
			_E("such a file is no executable - %s", argv[0]);
		} else {
			_E("unknown executable error - %s", argv[0]);
		}
		return -1;
	}
	/* never reach */
	return 0;
}

void __real_launch(const char *app_path, bundle * kb)
{
	int app_argc;
	char **app_argv;
	int i;

	app_argv = __create_argc_argv(kb, &app_argc, app_path);

	for (i = 0; i < app_argc; i++)
		_D("input argument %d : %s##", i, app_argv[i]);

	PERF("setup argument done");
	_D("lock up test log(no error) : setup argument done");

	/* Temporary log: launch time checking */
	LOG(LOG_DEBUG, "LAUNCH", "[%s:Platform:launchpad:done]", app_path);

	__normal_fork_exec(app_argc, app_argv);

	for(i=0; i<app_argc; i++) {
		if(app_argv[i]) free(app_argv[i]);
	}
	free(app_argv);
}


/*
 * Parsing original app path to retrieve default bundle
 *
 * -1 : Invalid sequence
 * -2 : Buffer overflow
 *
 */
static inline int __parser(const char *arg, char *out, int out_size)
{
	register int i;
	int state = 1;
	char *start_out = out;

	if (arg == NULL || out == NULL) {
		/* Handles null buffer*/
		return 0;
	}

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
		case 2:	/* escape start*/
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
		case 4:	/* character escape*/
			if (arg[i] == '\0') {
				state = 6;
			} else {
				*out = arg[i];
				out++;
				out_size--;
				state = 1;
			}
			break;
		case 5:	/* token*/
			if (out != start_out) {
				*out = '\0';
				out_size--;
				return i;
			}
			i--;
			state = 1;
			break;
		case 6:
			return -1;	/* error*/
		case 7:	/* terminate*/
			*out = '\0';
			out_size--;
			return 0;
		default:
			state = 6;
			break;	/* error*/
		}
	}

	if (out_size == 1) {
		*out = '\0';
	}
	/* Buffer overflow*/
	return -2;
}

void __modify_bundle(bundle * kb, int caller_pid,
			    app_info_from_db * menu_info, int cmd)
{
	bundle_del(kb, AUL_K_PKG_NAME);
	bundle_del(kb, AUL_K_EXEC);
	bundle_del(kb, AUL_K_PACKAGETYPE);
	bundle_del(kb, AUL_K_HWACC);

	/* Parse app_path to retrieve default bundle*/
	if (cmd == APP_START || cmd == APP_START_RES || cmd == APP_OPEN
		|| cmd == APP_RESUME)
	{
		char *ptr;
		char exe[MAX_PATH_LEN];
		int flag;

		ptr = _get_original_app_path(menu_info);

		flag = __parser(ptr, exe, sizeof(exe));
		if (flag > 0) {
			char key[256];
			char value[256];

			ptr += flag;
			_D("parsing app_path: EXEC - %s\n", exe);

			do {
				flag = __parser(ptr, key, sizeof(key));
				if (flag <= 0)
					break;
				ptr += flag;

				flag = __parser(ptr, value, sizeof(value));
				if (flag < 0)
					break;
				ptr += flag;

				/*bundle_del(kb, key);*/
				bundle_add(kb, key, value);
			} while (flag > 0);
		} else if (flag == 0) {
			_D("parsing app_path: No arguments\n");
		} else {
			_D("parsing app_path: Invalid argument\n");
		}
	}
}

int __send_to_sigkill(int pid)
{
	int pgid;

	pgid = getpgid(pid);
	if (pgid <= 1)
		return -1;

	if (killpg(pgid, SIGKILL) < 0)
		return -1;

	return 0;
}

int __term_app(int pid)
{
	int dummy;
	if (__app_send_raw
	    (pid, APP_TERM_BY_PID, (unsigned char *)&dummy, sizeof(int)) < 0) {
		_D("terminate packet send error - use SIGKILL");
		if (__send_to_sigkill(pid) < 0) {
			_E("fail to killing - %d\n", pid);
			return -1;
		}
	}
	_D("term done\n");
	return 0;
}

static int __get_caller_pid(bundle *kb)
{
	const char *pid_str;
	int pid;

	pid_str = bundle_get_val(kb, AUL_K_ORG_CALLER_PID);
	if(pid_str)
		goto end;

	pid_str = bundle_get_val(kb, AUL_K_CALLER_PID);
	if (pid_str == NULL)
		return -1;

end:
	pid = atoi(pid_str);
	if (pid <= 1)
		return -1;

	return pid;
}

int __foward_cmd(int cmd, bundle *kb, int cr_pid)
{
	int pid;
	char tmp_pid[MAX_PID_STR_BUFSZ];
	int datalen;
	bundle_raw *kb_data;
	int res;

	if ((pid = __get_caller_pid(kb)) < 0)
			return AUL_R_ERROR;

	snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", cr_pid);

	bundle_add(kb, AUL_K_CALLEE_PID, tmp_pid);

	bundle_encode(kb, &kb_data, &datalen);
	if ((res = __app_send_raw_with_noreply(pid, cmd, kb_data, datalen)) < 0)
		res = AUL_R_ERROR;

	free(kb_data);

	return res;
}

void __real_send(int clifd, int ret)
{
	if (send(clifd, &ret, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE) {
			_E("send failed due to EPIPE.\n");
		}
		_E("send fail to client");
	}

	close(clifd);
}

void __send_result_to_caller(int clifd, int ret)
{
	char *cmdline;
	int wait_count;
	int cmdline_changed = 0;
	int cmdline_exist = 0;

	if (clifd == -1)
		return;

	if (ret <= 1) {
		__real_send(clifd, ret);
		return;
	}
	/* check normally was launched?*/
	wait_count = 1;
	do {
		cmdline = __proc_get_cmdline_bypid(ret);
		if (cmdline == NULL) {
			_E("error founded when being launched with %d", ret);

		} else if (strcmp(cmdline, launchpad_cmdline)) {
			free(cmdline);
			cmdline_changed = 1;
			break;
		} else {
			cmdline_exist = 1;
			free(cmdline);
		}

		_D("-- now wait to change cmdline --");
		usleep(50 * 1000);	/* 50ms sleep*/
		wait_count++;
	} while (wait_count <= 20);	/* max 50*20ms will be sleep*/

	if ((!cmdline_exist) && (!cmdline_changed)) {
		_E("abnormally launched");
		__real_send(clifd, -1);	/* abnormally launched*/
		return;
	}

	if (!cmdline_changed)
		_E("process launched, but cmdline not changed");

	__real_send(clifd, ret);
	return;
}

static app_info_from_db *_get_app_info_from_bundle_by_pkgname(
	const char *pkgname, bundle *kb)
{
	app_info_from_db *menu_info;

	menu_info = calloc(1, sizeof(app_info_from_db));
	if (menu_info == NULL) {
		return NULL;
	}

	menu_info->pkg_name = strdup(pkgname);
	menu_info->app_path = strdup(bundle_get_val(kb, AUL_K_EXEC));
	if (menu_info->app_path != NULL)
		menu_info->original_app_path = strdup(menu_info->app_path);
	menu_info->pkg_type = strdup(bundle_get_val(kb, AUL_K_PACKAGETYPE));
	menu_info->hwacc = strdup(bundle_get_val(kb, AUL_K_HWACC));

	if (!_get_app_path(menu_info)) {
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	return menu_info;
}

/**
 * free after use it
 */
int get_native_appid(const char* app_path, char** appid) {
	int rc = smack_lgetlabel(app_path, appid, SMACK_LABEL_ACCESS);

	if (rc != 0 || *appid == NULL) {
		_E("smack_lgetlabel fail");
		return -1;
	}

	if (strlen(*appid) != APPID_LEN) {
		_E("wrong native appid : %s", *appid);
		return -1;
	}

	if (strlen(app_path) < sizeof(PATH_NATIVE_APP)+APPID_LEN-1) {
		_E("wrong native app_path : %s", app_path);
		return -1;
	}
	else if ( strncmp(app_path, PATH_NATIVE_APP, sizeof(PATH_NATIVE_APP)-1)
		|| strncmp(&app_path[sizeof(PATH_NATIVE_APP)-1]
		, *appid,APPID_LEN) )
	{
		_E("wrong native app_path : %s", app_path);
		return -1;
	}
	
	_D("get_appid return : %s", *appid);
	return 0;
}

int apply_smack_rules(const char* subject, const char* object
	, const char* access_type)
{
	struct smack_accesses *rules = NULL;

	_D("apply_smack_rules : %s %s %s", subject, object, access_type);

	if (smack_accesses_new(&rules)) {
		_E("smack_accesses_new fail");
		return -1;
	}

	if (smack_accesses_add(rules, subject, object, access_type)) {
		smack_accesses_free(rules);
		_E("smack_accesses_add fail");
		return -1;
	}

	if (smack_accesses_apply(rules)) {
		smack_accesses_free(rules);
		_E("smack_accesses_apply fail");
		return -1;
	}

	smack_accesses_free(rules);

	return 0;
}

int __prepare_valgrind_outputfile(bundle *kb)
{
	const char *str = NULL;
	const char **str_array = NULL;
	int len = 0;
	int i;

	if(bundle_get_type(kb, DLP_K_VALGRIND_ARG) & BUNDLE_TYPE_ARRAY) {
		str_array = bundle_get_str_array(kb, DLP_K_VALGRIND_ARG, &len);
	} else {
		str = bundle_get_val(kb, DLP_K_VALGRIND_ARG);
		if(str) {
			str_array = &str;
			len = 1;
		}
	}
	if(str_array == NULL) return 0;

	for (i = 0; i < len; i++) {
		if(str_array[i] == NULL) break;
		/* valgrind log file option */
		if (strncmp(str_array[i], OPT_VALGRIND_LOGFILE
			, strlen(OPT_VALGRIND_LOGFILE)) == 0)
		{
			if(strncmp(str_array[i], OPT_VALGRIND_LOGFILE_FIXED
				, strlen(str_array[i])))
			{
				_E("wrong valgrind option(%s). It should be %s"
					, str_array[i]
					, OPT_VALGRIND_LOGFILE_FIXED);
				return 1;
			}else{
				poll_outputfile |= POLL_VALGRIND_LOGFILE;
				if(remove(PATH_VALGRIND_LOGFILE)){
					_D("cannot remove %s"
						, PATH_VALGRIND_LOGFILE);
				}
			}
		}
		/* valgrind xml file option */
		else if (strncmp(str_array[i], OPT_VALGRIND_XMLFILE
			, strlen(OPT_VALGRIND_XMLFILE)) == 0)
		{
			if(strncmp(str_array[i], OPT_VALGRIND_XMLFILE_FIXED
				, strlen(str_array[i])))
			{
				_E("wrong valgrind option(%s). It should be %s"
					, str_array[i]
					, OPT_VALGRIND_XMLFILE_FIXED);
				return 1;
			}else{
				poll_outputfile |= POLL_VALGRIND_XMLFILE;
				if(remove(PATH_VALGRIND_XMLFILE)){
					_D("cannot remove %s"
						, PATH_VALGRIND_XMLFILE);
				}
			}
		}
	}
	return 0;
}

extern int capset(cap_user_header_t hdrp, const cap_user_data_t datap);

int __adjust_process_capability(int sv)
{
	static struct __user_cap_header_struct h;
	static struct __user_cap_data_struct ori_d[_LINUX_CAPABILITY_U32S_2];
	static struct __user_cap_data_struct inh_d[_LINUX_CAPABILITY_U32S_2];
	static int isinit = 0;

	if(isinit==0) {
		h.version = _LINUX_CAPABILITY_VERSION_2;
		h.pid = getpid();

		capget(&h, ori_d);
		capget(&h, inh_d);

		inh_d[CAP_TO_INDEX(CAP_NET_RAW)].inheritable |=
			CAP_TO_MASK(CAP_NET_RAW);
		inh_d[CAP_TO_INDEX(CAP_SYS_CHROOT)].inheritable |=
			CAP_TO_MASK(CAP_SYS_CHROOT);

		isinit++;

		if(sv == CAPABILITY_SET_ORIGINAL) return 0;
	}

	if(isinit==0) {
		_E("__adjust_process_capability init failed");
		return -1;
	}

	if(sv == CAPABILITY_SET_ORIGINAL) {
		h.pid = getpid();
		if (capset(&h, ori_d) < 0) {
			_E("Capability setting error");
			return -1;
		}
	}
	else if (sv == CAPABILITY_SET_INHERITABLE) {
		h.pid = getpid();
		if (capset(&h, inh_d) < 0) {
			_E("Capability setting error");
			return -1;
		}
	}

	return 0;
}

int __adjust_file_capability(const char * path)
{
	if(cap_set_file(path,cap_from_text("CAP_NET_RAW,CAP_SYS_CHROOT+i"))) {
		_E("cap_set_file failed : %s", path);
		return -1;
	}
	return 0;
}

int __prepare_fork(bundle *kb, char *appid)
{
	const char *str = NULL;
	const char **str_array = NULL;
	int len = 0;
	int i;

	need_to_set_inh_cap_after_fork=0;
	poll_outputfile = 0;
	if(bundle_get_type(kb, AUL_K_SDK) & BUNDLE_TYPE_ARRAY) {
		str_array = bundle_get_str_array(kb, AUL_K_SDK, &len);
	} else {
		str = bundle_get_val(kb, AUL_K_SDK);
		if(str) {
			str_array = &str;
			len = 1;
		}
	}
	if(str_array == NULL) return 0;

	is_gdbserver_launched = 0;
	gdbserver_pid = -1;
	gdbserver_app_pid = -1;

	for (i = 0; i < len; i++) {
		if(str_array[i] == NULL) break;
		/* gdbserver */
		if (strncmp(str_array[i], SDK_DEBUG, strlen(str_array[i])) == 0)
		{
			if(apply_smack_rules("sdbd",appid,"w")) {
				_E("unable to set sdbd rules");
				return 1;
			}

			// FIXME: set gdbfolder to 755 also
			if(dlp_chmod(PATH_GDBSERVER
				, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP
				|S_IROTH|S_IXOTH
				, 1))
			{
				_D("unable to set 755 to %s", PATH_GDBSERVER);
			}
			__adjust_file_capability(PATH_GDBSERVER);
			need_to_set_inh_cap_after_fork++;
			is_gdbserver_launched++;
		}
		/* valgrind */
		else if (strncmp(str_array[i], SDK_VALGRIND
			, strlen(str_array[i])) == 0)
		{
			if (__prepare_valgrind_outputfile(kb)) return 1;
			__adjust_file_capability(PATH_MEMCHECK);
		}
	}
	return 0;
}

/* chmod and chsmack to read file without root privilege */
void __chmod_chsmack_toread(const char * path)
{
	/* chmod */
	if(dlp_chmod(path, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH, 0))
	{
		_E("unable to set 644 to %s", path);
	}else{
		_D("set 644 to %s", path);
	}

	/* chsmack */
	if(smack_setlabel(path, "*", SMACK_LABEL_ACCESS))
	{
		_E("failed chsmack -a \"*\" %s", path);
	}else{
		_D("chsmack -a \"*\" %s", path);
	}

	return;
}

/* waiting for creating outputfile by child process */
void __waiting_outputfile()
{
	int wait_count = 0;
	while(poll_outputfile && wait_count<10) {
		/* valgrind log file */
		if( (poll_outputfile & POLL_VALGRIND_LOGFILE) 
			&& (access(PATH_VALGRIND_LOGFILE,F_OK)==0) )
		{
			__chmod_chsmack_toread(PATH_VALGRIND_LOGFILE);
			poll_outputfile &= ~POLL_VALGRIND_LOGFILE;
		}

		/* valgrind xml file */
		if( (poll_outputfile & POLL_VALGRIND_XMLFILE)
			&& (access(PATH_VALGRIND_XMLFILE,F_OK)==0) )
		{
			__chmod_chsmack_toread(PATH_VALGRIND_XMLFILE);
			poll_outputfile &= ~POLL_VALGRIND_XMLFILE;
		}
		
		if(poll_outputfile) {
			_D("-- now wait for creating the file --");
			usleep(50 * 1000);	/* 50ms sleep*/
			wait_count++;
		}
	}

	if(wait_count==10) _E("faild to waiting");
	return;
}

int __stdout_stderr_redirection(int defpid)
{
	char defpath[UNIX_PATH_MAX];
	int deffd, result=0; 

	/* stdout */
	snprintf(defpath, UNIX_PATH_MAX, "/proc/%d/fd/1", defpid);
	deffd = open(defpath,O_WRONLY);
	if(deffd < 0) {
		_E("opening caller(%d) stdout failed due to %s"
			, defpid, strerror(errno));
		result++;
	}else{
		dup2(deffd, 1);
		close(deffd);
	}

	/* stderr */
	snprintf(defpath, UNIX_PATH_MAX, "/proc/%d/fd/2", defpid);
	deffd = open(defpath,O_WRONLY);
	if(deffd < 0) {
		_E("opening caller(%d) stderr failed due to %s"
			, defpid,strerror(errno));
		result+=2;
	}else{
		dup2(deffd, 2);
		close(deffd);
	}

	return result;
}

void __launchpad_main_loop(int main_fd)
{
	bundle *kb = NULL;
	app_pkt_t *pkt = NULL;
	app_info_from_db *menu_info = NULL;

	const char *pkg_name = NULL;
	const char *app_path = NULL;
	int pid = -1;
	int clifd = -1;
	struct ucred cr;
	int is_real_launch = 0;

	char sock_path[UNIX_PATH_MAX] = {0,};
	char * appid = NULL;

	pkt = __app_recv_raw(main_fd, &clifd, &cr);
	if (!pkt) {
		_D("packet is NULL");
		goto end;
	}

	kb = bundle_decode(pkt->data, pkt->len);
	if (!kb) {
		_D("bundle decode error");
		goto end;
	}

	INIT_PERF(kb);
	PERF("packet processing start");

	pkg_name = bundle_get_val(kb, AUL_K_PKG_NAME);
	_D("pkg name : %s\n", pkg_name);

	menu_info = _get_app_info_from_bundle_by_pkgname(pkg_name, kb);
	if (menu_info == NULL) {
		_D("such pkg no found");
		goto end;
	}

	app_path = _get_app_path(menu_info);
	if(app_path == NULL) {
		_E("app_path is NULL");
		goto end;
	}
	if (app_path[0] != '/') {
		_D("app_path is not absolute path");
		goto end;
	}

	{
		int rc = get_native_appid(app_path,&appid);
		if(rc!=0 || appid==NULL) {
			_E("unable to get native appid");
			if(appid){
				free(appid);
				appid = NULL;
			}
			goto end;
		}
	}

	__modify_bundle(kb, cr.pid, menu_info, pkt->cmd);
	pkg_name = _get_pkgname(menu_info);

	PERF("get package information & modify bundle done");

	if(__prepare_fork(kb,appid)) goto end;

	pid = fork();
	if (pid == 0) {
		if(need_to_set_inh_cap_after_fork) {
			__adjust_process_capability(CAPABILITY_SET_INHERITABLE);
		}
		PERF("fork done");
		_D("lock up test log(no error) : fork done");

		close(clifd);
		close(main_fd);
		__signal_unset_sigchld();
		__signal_fini();

		snprintf(sock_path, UNIX_PATH_MAX, "%s/%d", AUL_SOCK_PREFIX
			, getpid());
		unlink(sock_path);

		if(__stdout_stderr_redirection(__get_caller_pid(kb))) {
			_E("__stdout_stderr_redirection fail");
		}

		PERF("prepare exec - first done");
		_D("lock up test log(no error) : prepare exec - first done");

		if (__prepare_exec(pkg_name, app_path,
				   menu_info, kb) < 0) {
			_E("preparing work fail to launch - "
			   "can not launch %s\n", pkg_name);
			exit(-1);
		}

		PERF("prepare exec - second done");
		_D("lock up test log(no error) : prepare exec - second done");

		__real_launch(app_path, kb);

		exit(-1);
	}

	if(is_gdbserver_launched) {
		char buf[MAX_LOCAL_BUFSZ];

		usleep(100 * 1000);	/* 100ms sleep */
		snprintf(buf, MAX_LOCAL_BUFSZ, "%s.exe", app_path);
		gdbserver_app_pid = __proc_iter_cmdline(NULL, buf);

		if(gdbserver_app_pid == -1) {
			_E("faild to get app pid");
		} else {
			gdbserver_pid = pid;
			pid = gdbserver_app_pid;
		}
	}

	_D("==> real launch pid : %d %s\n", pid, app_path);
	is_real_launch = 1;

 end:
	__send_result_to_caller(clifd, pid);

	if (pid > 0) {
		if (is_real_launch) {
			/*TODO: retry*/
			__signal_block_sigchld();
			__send_app_launch_signal(pid);
			__signal_unblock_sigchld();
		}
	}

	if (menu_info != NULL)
		_free_app_info_from_db(menu_info);

	if (kb != NULL)
		bundle_free(kb);
	if (pkt != NULL)
		free(pkt);
	if (appid != NULL) 
		free(appid);

	/* Active Flusing for Daemon */
	if (initialized > AUL_POLL_CNT) {
		sqlite3_release_memory(SQLITE_FLUSH_MAX);
		malloc_trim(0);
		initialized = 1;
	}

	if(poll_outputfile) __waiting_outputfile();
}

int __launchpad_pre_init(int argc, char **argv)
{
	int fd;

	/* signal init*/
	__signal_init();

	/* get my(launchpad) command line*/
	launchpad_cmdline = __proc_get_cmdline_bypid(getpid());
	if (launchpad_cmdline == NULL) {
		_E("launchpad cmdline fail to get");
		return -1;
	}
	_D("launchpad cmdline = %s", launchpad_cmdline);

	/* create launchpad sock        */
	fd = __create_server_sock(DEBUG_LAUNCHPAD_PID);
	if (fd < 0) {
		_E("server sock error");
		return -1;
	}

	__preload_init(argc, argv);

	__preexec_init(argc, argv);

	return fd;
}

int __launchpad_post_init()
{
	/* Setting this as a global variable to keep track 
	of launchpad poll cnt */
	/* static int initialized = 0;*/

	if (initialized) {
		initialized++;
		return 0;
	}

	if (__signal_set_sigchld() < 0)
		return -1;

	initialized++;

	return 0;
}

int main(int argc, char **argv)
{
	int main_fd;
	struct pollfd pfds[POLLFD_MAX];
	int i;

	__adjust_process_capability(CAPABILITY_SET_ORIGINAL);

	/* init without concerning X & EFL*/
	main_fd = __launchpad_pre_init(argc, argv);
	if (main_fd < 0) {
		_E("launchpad pre init failed");
		exit(-1);
	}

	pfds[0].fd = main_fd;
	pfds[0].events = POLLIN;
	pfds[0].revents = 0;

	while (1) {
		if (poll(pfds, POLLFD_MAX, -1) < 0)
			continue;

		/* init with concerning X & EFL (because of booting 
		sequence problem)*/
		if (__launchpad_post_init() < 0) {
			_E("launcpad post init failed");
			exit(-1);
		}

		for (i = 0; i < POLLFD_MAX; i++) {
			if ((pfds[i].revents & POLLIN) != 0) {
				__launchpad_main_loop(pfds[i].fd);
			}
		}
	}
}

