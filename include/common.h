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

#ifndef __COMMON_H__
#define __COMMON_H__

#define _GNU_SOURCE
#include <unistd.h>
#include <ctype.h>
#include <dlog.h>
#include <bundle.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "DEBUG_LAUNCHPAD"
#endif

#define _E(fmt, arg...) LOGE(fmt, ##arg)
#define _D(fmt, arg...) LOGD(fmt, ##arg)
#define _W(fmt, arg...) LOGW(fmt, ##arg)

#define SOCKET_PATH "/run/user"
#define MAX_LOCAL_BUFSZ 128
#define AUL_SOCK_MAXBUFF 131071

#define PAD_CMD_LAUNCH 0

typedef struct _app_pkt_t {
	int cmd;
	int len;
	int opt;
	unsigned char data[1];
} app_pkt_t;

typedef struct {
	char *appid;
	char *app_path;
	char *original_app_path;
	char *debug_appid;
	char *pkg_type;
	char *hwacc;
	char *taskmanage;
	char *comp_type;
} appinfo_t;

struct ucred;

int _create_server_sock(void);
app_pkt_t *_recv_pkt_raw(int fd, int *clifd, struct ucred *cr);

appinfo_t *_appinfo_create(bundle *kb);
void _appinfo_free(appinfo_t *appinfo);
void _modify_bundle(bundle *kb, int caller_pid, appinfo_t *appinfo, int cmd);

void _set_env(appinfo_t *app_info, bundle *kb);
char **_create_argc_argv(bundle *kb, int *margc, const char *app_path);

int _proc_check_cmdline_bypid(int pid);

#endif /* __COMMON_H__ */

