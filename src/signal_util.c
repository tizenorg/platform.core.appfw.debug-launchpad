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
#include <signal.h>
#include <sys/smack.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signalfd.h>
#include <dirent.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "defs.h"
#include "common.h"
#include "file_util.h"
#include "debug_util.h"
#include "signal_util.h"

#define AUL_DBUS_PATH "/aul/dbus_handler"
#define AUL_DBUS_SIGNAL_INTERFACE "org.tizen.aul.signal"
#define AUL_DBUS_APPDEAD_SIGNAL "app_dead"
#define AUL_DBUS_APPLAUNCH_SIGNAL "app_launch"

#define PATH_VALGRIND_XMLFILE "/tmp/valgrind_result.xml"

static DBusConnection *bus = NULL;
static sigset_t oldmask;

static void __socket_garbage_collector(void)
{
	DIR *dp;
	struct dirent *dentry;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%d", SOCKET_PATH, getuid());
	dp = opendir(path);
	if (dp == NULL)
		return;

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		snprintf(path, sizeof(path), "/proc/%s", dentry->d_name);
		if (access(path, F_OK) != 0) { /* Flawfinder: ignore */
			snprintf(path, sizeof(path), "%s/%d/%s",
					SOCKET_PATH, getuid(), dentry->d_name);
			unlink(path);
			continue;
		}
	}

	closedir(dp);
}

int _send_app_dead_signal(int dead_pid)
{
	DBusMessage *message;

	if (bus == NULL)
		return -1;

	message = dbus_message_new_signal(AUL_DBUS_PATH,
			AUL_DBUS_SIGNAL_INTERFACE,
			AUL_DBUS_APPDEAD_SIGNAL);

	if (dbus_message_append_args(message,
				DBUS_TYPE_UINT32, &dead_pid,
				DBUS_TYPE_INVALID) == FALSE) {
		_E("Failed to load data error");
		return -1;
	}

	if (dbus_connection_send(bus, message, NULL) == FALSE) {
		_E("dbus send error");
		return -1;
	}

	dbus_connection_flush(bus);
	dbus_message_unref(message);

	_D("send dead signal done\n");

	return 0;
}

int _send_app_launch_signal(int launch_pid)
{
	DBusMessage *message;

	if (bus == NULL)
		return -1;

	message = dbus_message_new_signal(AUL_DBUS_PATH,
			AUL_DBUS_SIGNAL_INTERFACE,
			AUL_DBUS_APPLAUNCH_SIGNAL);

	if (dbus_message_append_args(message,
				DBUS_TYPE_UINT32, &launch_pid,
				DBUS_TYPE_INVALID) == FALSE) {
		_E("Failed to load data error");
		return -1;
	}

	if (dbus_connection_send(bus, message, NULL) == FALSE) {
		_E("dbus send error");
		return -1;
	}

	dbus_connection_flush(bus);
	dbus_message_unref(message);

	_D("send launch signal done\n");

	return 0;
}

static int __sigchild_action(void *data)
{
	pid_t dead_pid;
	char buf[MAX_LOCAL_BUFSZ];

	dead_pid = (pid_t)(intptr_t)data;
	if (dead_pid <= 0)
		return -1;

	/* send app pid instead of gdbserver pid */
	if (dead_pid == _get_gdbserver_pid())
		dead_pid = _get_gdbserver_app_pid();

	/* valgrind xml file */
	if (access(PATH_VALGRIND_XMLFILE, F_OK) == 0)
		_change_file(PATH_VALGRIND_XMLFILE);

	_send_app_dead_signal(dead_pid);

	snprintf(buf, MAX_LOCAL_BUFSZ, "%s/%d/%d", SOCKET_PATH, getuid(), dead_pid);
	unlink(buf);

	__socket_garbage_collector();

	return 0;
}

void _debug_launchpad_sigchld(struct signalfd_siginfo *info)
{
	int status;
	pid_t child_pid;
	pid_t child_pgid;

	child_pgid = getpgid(info->ssi_pid);
	_D("dead pid = %d pgid = %d", info->ssi_pid, child_pgid);

	while ((child_pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (child_pid == child_pgid)
			killpg(child_pgid, SIGKILL);
		__sigchild_action((void *)(intptr_t)child_pid);
	}
}

int _signal_init(void)
{
	int i;
	DBusError error;

	dbus_error_init(&error);
	dbus_threads_init_default();
	bus = dbus_bus_get_private(DBUS_BUS_SESSION, &error);
	if (!bus) {
		_E("Failed to connect to the D-BUS daemon: %s", error.message);
		dbus_error_free(&error);
		return -1;
	}

	for (i = 0; i < _NSIG; i++) {
		switch (i) {
		/* controlled by sys-assert package*/
		case SIGQUIT:
		case SIGILL:
		case SIGABRT:
		case SIGBUS:
		case SIGFPE:
		case SIGSEGV:
		case SIGPIPE:
			break;
		default:
			signal(i, SIG_DFL);
			break;
		}
	}

	return 0;
}

int _signal_get_sigchld_fd(void)
{
	sigset_t mask;
	int sfd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, &oldmask) == -1)
		_E("sigprocmask() is failed.");

	sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sfd == -1) {
		_E("Failed to create signal fd");
		return -1;
	}

	return sfd;
}

int _signal_unblock_sigchld(void)
{
	if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0) {
		_E("SIG_SETMASK error");
		return -1;
	}

	_D("SIGCHLD unblocked");

	return 0;
}

int _signal_fini(void)
{
	int i;

	if (bus)
		dbus_connection_close(bus);

#ifndef PRELOAD_ACTIVATE
	for (i = 0; i < _NSIG; i++)
		signal(i, SIG_DFL);
#endif
	return 0;
}
