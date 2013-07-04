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


#include <pthread.h>
#include "app_signal.h"

static struct sigaction old_sigchild;
static DBusConnection *bus = NULL;
sigset_t oldmask;

static inline void __socket_garbage_collector()
{
	DIR *dp;
	struct dirent *dentry;
	char tmp[MAX_LOCAL_BUFSZ];

	dp = opendir(AUL_SOCK_PREFIX);
	if (dp == NULL)
		return;

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		snprintf(tmp, MAX_LOCAL_BUFSZ, "/proc/%s", dentry->d_name);
		if (access(tmp, F_OK) < 0) {	/* Flawfinder: ignore */
			snprintf(tmp, MAX_LOCAL_BUFSZ, "%s/%s", AUL_SOCK_PREFIX,
				 dentry->d_name);
			unlink(tmp);
			continue;
		}
	}
	closedir(dp);
}

static inline int __send_app_dead_signal(int dead_pid)
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

static inline int __send_app_launch_signal(int launch_pid)
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

	dead_pid = (pid_t) data;
	if (dead_pid <= 0)
		goto end;

	__send_app_dead_signal(dead_pid);

	snprintf(buf, MAX_LOCAL_BUFSZ, "%s/%d", AUL_SOCK_PREFIX, dead_pid);
	unlink(buf);

	__socket_garbage_collector();
 end:
	return 0;
}

static void __launchpad_sig_child(int signo, siginfo_t *info, void *data)
{
	int status;
	pid_t child_pid;
	pid_t child_pgid;

	child_pgid = getpgid(info->si_pid);
	_D("dead_pid = %d pgid = %d", info->si_pid, child_pgid);

	while ((child_pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (child_pid == child_pgid)
			killpg(child_pgid, SIGKILL);
		__sigchild_action((void *)child_pid);
	}

	return;
}

static inline int __signal_init(void)
{
	int i;
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

static inline int __signal_set_sigchld(void)
{
	struct sigaction act;
	DBusError error;

	dbus_error_init(&error);
	dbus_threads_init_default();
	bus = dbus_bus_get_private(DBUS_BUS_SYSTEM, &error);
	if (!bus) {
		_E("Failed to connect to the D-BUS daemon: %s", error.message);
		dbus_error_free(&error);
		return -1;
	}
	/* TODO: if process stop mechanism is included, 
	should be modified (SA_NOCLDSTOP)*/
	act.sa_handler = NULL;
	act.sa_sigaction = __launchpad_sig_child;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;

	if (sigaction(SIGCHLD, &act, &old_sigchild) < 0)
		return -1;

	return 0;
}

static inline int __signal_unset_sigchld(void)
{
	struct sigaction dummy;

	if (bus == NULL)
		return 0;

	dbus_connection_close(bus);
	if (sigaction(SIGCHLD, &old_sigchild, &dummy) < 0)
		return -1;

	return 0;
}

static inline int __signal_block_sigchld(void)
{
	sigset_t newmask;

	sigemptyset(&newmask);
	sigaddset(&newmask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &newmask, &oldmask) < 0) {
		_E("SIG_BLOCK error");
		return -1;
	}

	_D("SIGCHLD blocked");

	return 0;
}

static inline int __signal_unblock_sigchld(void)
{
	if(sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0) {
		_E("SIG_SETMASK error");
		return -1;
	}

	_D("SIGCHLD unblocked");
	return 0;
}

static inline int __signal_fini(void)
{
#ifndef PRELOAD_ACTIVATE
	int i;
	for (i = 0; i < _NSIG; i++)
		signal(i, SIG_DFL);
#endif
	return 0;
}

