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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/signalfd.h>
#include <linux/limits.h>
#include <glib.h>
#include <dlog.h>
#include <bundle.h>
#include <bundle_internal.h>

#include "common.h"
#include "signal_util.h"
#include "security_util.h"
#include "file_util.h"
#include "debug_util.h"
#include "perf.h"
#include "defs.h"
#include "preload.h"

#define AUL_PR_NAME 16

static int __real_send(int clifd, int ret)
{
	if (send(clifd, &ret, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE) {
			_E("send failed due to EPIPE.\n");
			close(clifd);
			return -1;
		}

		_E("send fail to client");
	}

	close(clifd);

	return 0;
}

static void __send_result_to_caller(int clifd, int ret, const char* app_path)
{
	char *cmdline;
	int wait_count;
	int cmdline_changed = 0;
	int cmdline_exist = 0;
	char sock_path[PATH_MAX];

	_W("Check app launching");

	if (clifd == -1)
		return;

	if (ret <= 1) {
		_E("launching failed");
		__real_send(clifd, ret);
		return;
	}

	/* check normally was launched? */
	wait_count = 1;
	do {
		cmdline = _proc_get_cmdline_bypid(ret);
		if (cmdline == NULL) {
			_E("error founded when being launched with %d", ret);
			if (cmdline_exist || cmdline_changed) {
				_E("The app process might be terminated while we are wating %d", ret);
				break;
			}
		} else if (strcmp(cmdline, app_path) == 0) {
			/* Check app main loop is prepared or not */
			_D("-- now wait app mainloop creation --");
			free(cmdline);
			cmdline_changed = 1;

			snprintf(sock_path, sizeof(sock_path), "%s/%d/%d",
					SOCKET_PATH, getuid(), ret);
			if (access(sock_path, F_OK) == 0)
				break;

		} else {
			_D("-- now wait cmdline changing --");
			cmdline_exist = 1;
			free(cmdline);
		}

		usleep(50 * 1000); /* 50ms sleep */
		wait_count++;
	} while (wait_count <= 20); /* max 50*20ms will be sleep */

	if ((!cmdline_exist) && (!cmdline_changed)) {
		_E("abnormally launched");
		__real_send(clifd, -1); /* abnormally launched*/
		return;
	}

	if (!cmdline_changed)
		_E("process launched, but cmdline not changed");

	if (__real_send(clifd, ret) < 0) {
		if (kill(ret, SIGKILL) == -1)
			_E("Failed to send SIGKILL: %d", errno);
	}

	return;
}

static int __prepare_exec(const char *appid, const char *app_path,
		appinfo_t *appinfo, bundle *kb)
{
	char *file_name;
	char process_name[AUL_PR_NAME];
	int ret;
	const char *value;

	/* Set new session ID & new process group ID */
	/* In linux, child can set new session ID without check permission */
	setsid();

	/* SET PRIVILEGES */
	value = bundle_get_val(kb, AUL_K_SDK);
	if (value && strncmp(value, SDK_ATTACH, strlen(SDK_ATTACH) != 0)) {
		_D("appid: %s / pkg_type: %s / app_path: %s",
				appid, appinfo->pkg_type, app_path);
		if ((ret = _set_access(appid)) != 0) {
			_E("Failed to set privileges - check your package's credential: %d", ret);
			return -1;
		}
	}

	/* SET DUMPABLE - for coredump */
	prctl(PR_SET_DUMPABLE, 1);

	/* SET PROCESS NAME */
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

	/* SET ENVIROMENT */
	_set_env(appinfo, kb);

	return 0;
}

static int __prepare_fork(bundle *kb, const char *appid)
{
	const char *str = NULL;
	const char **str_array = NULL;
	int len = 0;

	if (bundle_get_type(kb, AUL_K_SDK) & BUNDLE_TYPE_ARRAY)
		str_array = bundle_get_str_array(kb, AUL_K_SDK, &len);
	else {
		str = bundle_get_val(kb, AUL_K_SDK);
		if (str) {
			str_array = &str;
			len = 1;
		}
	}

	_prepare_debug_tool(kb, appid, str_array, len);

	return 0;
}

static int __normal_fork_exec(int argc, char **argv)
{
	_D("start real fork and exec\n");

	if (execv(argv[0], argv) < 0) { /* Flawfinder: ignore */
		if (errno == EACCES)
			_E("such a file is no executable - %s", argv[0]);
		else
			_E("unknown executable error - %s", argv[0]);

		return -1;
	}

	/* never reach */
	return 0;
}

static void __real_launch(const char *app_path, bundle *kb)
{
	int app_argc;
	char **app_argv;
	int i;

	app_argv = _create_argc_argv(kb, &app_argc, app_path);
	for (i = 0; i < app_argc; i++)
		_D("input argument %d : %s##", i, app_argv[i]);

	PERF("setup argument done");

	/* Temporary log: launch time checking */
	LOG(LOG_DEBUG, "LAUNCH", "[%s:Platform:launchpad:done]", app_path);

	__normal_fork_exec(app_argc, app_argv);
}

static int __start_process(const char *appid, const char *app_path,
		bundle *kb, appinfo_t *appinfo)
{
	char sock_path[PATH_MAX];
	int pid;
	int max_fd;
	int iter_fd;

	if (__prepare_fork(kb, appinfo->debug_appid) < 0)
		return -1;

	pid = fork();
	if (pid == 0) {
		PERF("fork done");
		_D("lock up test log(no error): fork done");

		_signal_unblock_sigchld();
		_signal_fini();

		max_fd = sysconf(_SC_OPEN_MAX);
		for (iter_fd = 3; iter_fd <= max_fd; iter_fd++)
			close(iter_fd);

		snprintf(sock_path, sizeof(sock_path), "%s/%d/%d",
				SOCKET_PATH, getuid(), getpid());
		unlink(sock_path);

		PERF("prepare exec - fisrt done");
		_D("lock up test log(no error): prepare exec - first done");

		if (__prepare_exec(appid, app_path, appinfo, kb) < 0) {
			_E("preparing work fail to launch - can not launch %s", appid);
			exit(-1);
		}

		PERF("prepare exec - second done");
		_D("lock up test log(no error): prepare exec - second done");
		__real_launch(app_path, kb);

		exit(-1);
	}

	_D("==> real launch pid: %d %s", pid, app_path);

	return pid;
}

static gboolean __handle_sigchld(gpointer data)
{
	GPollFD *gpollfd = (GPollFD *)data;
	int fd = gpollfd->fd;
	struct signalfd_siginfo siginfo;
	ssize_t s;

	do {
		s = read(fd, &siginfo, sizeof(struct signalfd_siginfo));
		if (s == 0)
			break;

		if (s != sizeof(struct signalfd_siginfo)) {
			_E("error reading sigchld info");
			break;
		}

		_debug_launchpad_sigchld(&siginfo);
	} while (s > 0);

	return TRUE;
}

static gboolean __handle_launch_event(gpointer data)
{
	GPollFD *gpollfd = (GPollFD *)data;
	int fd = gpollfd->fd;
	bundle *kb = NULL;
	app_pkt_t *pkt = NULL;
	appinfo_t *appinfo = NULL;
	const char *app_path = NULL;
	int pid = -1;
	int clifd = -1;
	struct ucred cr;

	pkt = _recv_pkt_raw(fd, &clifd, &cr);
	if (pkt == NULL) {
		_E("packet is NULL");
		return TRUE;
	}

	kb = bundle_decode(pkt->data, pkt->len);
	if (kb == NULL) {
		_E("bundle decode error");
		goto end;
	}

	INIT_PERF(kb);
	PERF("packet processing start");

	appinfo = _appinfo_create(kb);
	if (appinfo == NULL) {
		_E("_appinfo_create() is failed.");
		goto end;
	}

	app_path = appinfo->app_path;
	if (app_path == NULL) {
		_E("app_path is NULL");
		goto end;
	}

	if (app_path[0] != '/') {
		_E("app_path is not absolute path: %s", app_path);
		goto end;
	}

	_D("appid: %s", appinfo->appid);
	_D("exec: %s", appinfo->app_path);
	_D("debug appid: %s", appinfo->debug_appid);
	_D("hwacc: %s", appinfo->hwacc);

	_modify_bundle(kb, cr.pid, appinfo, pkt->cmd);
	if (appinfo->appid == NULL) {
		_E("unable to get appid from appinfo");
		goto end;
	}

	PERF("get package infomation & modify bundle done");

	pid = __start_process(appinfo->appid, app_path, kb, appinfo);

end:
	__send_result_to_caller(clifd, pid, app_path);

	if (pid > 0)
		_send_app_launch_signal(pid);
	if (appinfo)
		_appinfo_free(appinfo);
	if (kb)
		bundle_free(kb);
	if (pkt)
		free(pkt);
	if (_get_valgrind_option())
		_wait_for_valgrind_output();

	return TRUE;
}

static gboolean __glib_check(GSource *src)
{
	GSList *fd_list;
	GPollFD *tmp;

	fd_list = src->poll_fds;
	do {
		tmp = (GPollFD *)fd_list->data;
		if ((tmp->revents & (G_IO_IN | G_IO_PRI | G_IO_HUP | G_IO_NVAL)))
			return TRUE;
		fd_list = fd_list->next;
	} while (fd_list);

	return FALSE;
}

static gboolean __glib_dispatch(GSource *src, GSourceFunc callback, gpointer data)
{
	return callback(data);
}

static gboolean __glib_prepare(GSource *src, gint *timeout)
{
	return FALSE;
}

static GSourceFuncs funcs = {
	.prepare = __glib_prepare,
	.check = __glib_check,
	.dispatch = __glib_dispatch,
	.finalize = NULL
};

static int __poll_fd(int fd, GSourceFunc callback)
{
	int r;
	GPollFD *gpollfd;
	GSource *src;

	src = g_source_new(&funcs, sizeof(GSource));
	if (src == NULL) {
		_E("out of memory");
		return -1;
	}

	gpollfd = (GPollFD *)g_malloc(sizeof(GPollFD));
	if (gpollfd == NULL) {
		_E("out of memory");
		g_source_destroy(src);
		return -1;
	}

	gpollfd->fd = fd;
	gpollfd->events = G_IO_IN;

	g_source_add_poll(src, gpollfd);
	g_source_set_callback(src, callback, (gpointer)gpollfd, NULL);
	g_source_set_priority(src, G_PRIORITY_DEFAULT);

	r = g_source_attach(src, NULL);
	if (r == 0) {
		g_free(gpollfd);
		g_source_destroy(src);
		return -1;
	}

	return r;
}

static int __init_sigchld_fd(void)
{
	int fd;

	fd = _signal_get_sigchld_fd();
	if (fd < 0) {
		_E("Failed to get sigchld fd");
		return -1;
	}

	if (__poll_fd(fd, (GSourceFunc)__handle_sigchld) < 0) {
		close(fd);
		return -1;
	}

	return 0;
}

static int __init_debug_launchpad_fd(int argc, char **argv)
{
	int fd;

	/* signal init */
	_signal_init();

	/* create debug-launchpad socket */
	fd = _create_server_sock();
	if (fd < 0) {
		_E("Failed to create server socket");
		return -1;
	}

	if (__poll_fd(fd, (GSourceFunc)__handle_launch_event) < 0) {
		close(fd);
		return -1;
	}

	return 0;
}

static int __before_loop(int argc, char **argv)
{
	if (__init_sigchld_fd() < 0) {
		_E("Failed to initialize sigchld fd.");
		return -1;
	}

	if (__init_debug_launchpad_fd(argc, argv) < 0) {
		_E("Failed to initialize launchpad fd.");
		return -1;
	}

	__preload_init(argc, argv);

	return 0;
}

int main(int argc, char **argv)
{
	GMainLoop *loop;

	loop = g_main_loop_new(NULL, FALSE);
	if (loop == NULL) {
		_E("Failed to create glib main loop.");
		return -1;
	}

	if (__before_loop(argc, argv) < 0) {
		_E("Failed to initiailze debug-launchapd.");
		return -1;
	}

	g_main_loop_run(loop);

	return 0;
}
