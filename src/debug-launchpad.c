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
#include <security-manager.h>

#include "common.h"
#include "signal_util.h"
#include "debug_util.h"
#include "perf.h"
#include "defs.h"

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

static void __send_result_to_caller(int clifd, int ret)
{
	int res;
	int count = 0;
	char path[PATH_MAX];

	_W("Check app launching");

	if (clifd == -1)
		return;

	if (ret <= 1) {
		_E("launching failed");
		__real_send(clifd, ret);
		return;
	}

	snprintf(path, sizeof(path), "/run/aul/apps/%d/%d/.app-sock",
			getuid(), ret);
	_D("socket path: %s", path);
	do {
		if (access(path, F_OK) == 0) {
			_D("%s exists", path);
			break;
		}

		_D("-- now wait socket creation --");
		usleep(50 * 1000);
		count++;
	} while (count < 20);

	res = _proc_check_cmdline_bypid(ret);
	if (res < 0) {
		_E("The app process might be terminated "
				"while we are wating %d", ret);
		__real_send(clifd, -1); /* abnormally launched */
		return;
	}

	if (__real_send(clifd, ret) < 0) {
		if (kill(ret, SIGKILL) == -1)
			_E("Failed to send SIGKILL: %d", errno);
	}
}

static int __prepare_exec(const char *appid, const char *app_path,
		appinfo_t *appinfo, bundle *kb)
{
	char *file_name;
	char process_name[AUL_PR_NAME];
	int ret;

	/* Set new session ID & new process group ID */
	/* In linux, child can set new session ID without check permission */
	setsid();

	/* SET PRIVILEGES */
	_D("appid: %s / pkg_type: %s / app_path: %s",
			appid, appinfo->pkg_type, app_path);
	ret = security_manager_prepare_app(appid);
	if (ret != SECURITY_MANAGER_SUCCESS) {
		_E("Failed to set privileges "
				"- check your package's credential: %d", ret);
		return -1;
	}

	/* SET DUMPABLE - for coredump */
	prctl(PR_SET_DUMPABLE, 1);

	/* SET PROCESS NAME */
	if (app_path == NULL) {
		_D("app_path should not be NULL - check menu db");
		return -1;
	}

	file_name = strrchr(app_path, '/');
	if (file_name == NULL) {
		_D("file_name is NULL");
		return -1;
	}

	file_name++;
	if (*file_name == '\0') {
		_D("can't locate file name to execute");
		return -1;
	}

	_prepare_listen_sock();

	memset(process_name, '\0', AUL_PR_NAME);
	snprintf(process_name, AUL_PR_NAME, "%s", file_name);
	prctl(PR_SET_NAME, process_name);

	/* SET ENVIROMENT */
	_set_env(appinfo, kb);

	return 0;
}

static int __prepare_fork(bundle *kb, const char *appid)
{
	const char *str;
	const char **str_array = NULL;
	int len = 0;

	if (bundle_get_type(kb, AUL_K_SDK) & BUNDLE_TYPE_ARRAY) {
		str_array = bundle_get_str_array(kb, AUL_K_SDK, &len);
		if (str_array == NULL)
			return -1;
	} else {
		str = bundle_get_val(kb, AUL_K_SDK);
		if (str) {
			str_array = &str;
			len = 1;
		}
	}

	_prepare_debug_tool(kb, appid, str_array, len);

	return 0;
}

static int __stdout_stderr_redirection(int caller_pid)
{
	char path[PATH_MAX];
	int fd;
	int ret = 0;

	/* stdout */
	snprintf(path, sizeof(path), "/proc/%d/fd/1", caller_pid);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		_E("Failed to open %s [%s]", path, strerror(errno));
		ret++;
	} else {
		dup2(fd, 1);
		close(fd);
	}

	/* stderr */
	snprintf(path, sizeof(path), "/proc/%d/fd/2", caller_pid);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		_E("Failed to open %s [%s]", path, strerror(errno));
		ret += 2;
	} else {
		dup2(fd, 2);
		close(fd);
	}

	return ret;
}

static int __get_caller_pid(bundle *kb)
{
	const char *pid_str;
	int pid;

	pid_str = bundle_get_val(kb, AUL_K_ORG_CALLER_PID);
	if (pid_str == NULL)
		pid_str = bundle_get_val(kb, AUL_K_CALLER_PID);

	if (pid_str == NULL)
		return -1;

	pid = atoi(pid_str);
	if (pid <= 1)
		return -1;

	return pid;
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
	int app_argc = 0;
	char **app_argv;
	char *extra_data = NULL;
	int len;
	int r;
	int i;

	r = bundle_encode(kb, (bundle_raw **)&extra_data, &len);
	if (r != BUNDLE_ERROR_NONE)
		exit(-1);

	_set_extra_data(extra_data);
	free(extra_data);

	app_argv = _create_argc_argv(kb, &app_argc, app_path);
	if (app_argv == NULL)
		exit(-1);

	for (i = 0; i < app_argc; i++)
		_D("input argument %d : %s##", i, app_argv[i]);

	bundle_free(kb);
	PERF("setup argument done");

	__normal_fork_exec(app_argc, app_argv);
}

static int __start_process(const char *appid, const char *app_path,
		bundle *kb, appinfo_t *appinfo)
{
	int pid;

	if (__prepare_fork(kb, appinfo->debug_appid) < 0)
		return -1;

	pid = fork();
	if (pid == 0) {
		PERF("fork done");
		_D("lock up test log(no error): fork done");

		if (__stdout_stderr_redirection(__get_caller_pid(kb)))
			_E("__stdout_stderr_redirection() failed");

		_signal_unblock_sigchld();
		_signal_fini();

		_close_all_fds();
		_delete_sock_path(getpid(), getuid());

		PERF("prepare exec - fisrt done");
		_D("lock up test log(no error): prepare exec - first done");

		if (__prepare_exec(appid, app_path, appinfo, kb) < 0) {
			_E("preparing work fail to launch "
					"- can not launch %s", appid);
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
	__send_result_to_caller(clifd, pid);

	if (pid > 0)
		_send_app_launch_signal(pid, appinfo->appid);
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
		if ((tmp->revents &
				(G_IO_IN | G_IO_PRI | G_IO_HUP | G_IO_NVAL)))
			return TRUE;
		fd_list = fd_list->next;
	} while (fd_list);

	return FALSE;
}

static gboolean __glib_dispatch(GSource *src, GSourceFunc callback,
		gpointer data)
{
	return callback(data);
}

static gboolean __glib_prepare(GSource *src, gint *timeout)
{
	return FALSE;
}

static void __glib_finalize(GSource *src)
{
	GSList *fd_list;
	GPollFD *gpollfd;

	fd_list = src->poll_fds;
	do {
		gpollfd = (GPollFD *)fd_list->data;
		close(gpollfd->fd);
		g_free(gpollfd);

		fd_list = fd_list->next;
	} while (fd_list);
}

static GSourceFuncs funcs = {
	.prepare = __glib_prepare,
	.check = __glib_check,
	.dispatch = __glib_dispatch,
	.finalize = __glib_finalize
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

