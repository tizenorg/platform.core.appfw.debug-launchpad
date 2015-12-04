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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <dlog.h>
#include <bundle.h>

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "DEBUG_LAUNCHPAD"
#endif

#define _E(fmt, arg...) LOGE(fmt, ##arg)
#define _D(fmt, arg...) LOGD(fmt, ##arg)
#define _W(fmt, arg...) LOGW(fmt, ##arg)

#define AUL_K_STARTTIME "__AUL_STARTTIME__"
#define AUL_K_EXEC "__AUL_EXEC__"
#define AUL_K_PACKAGETYPE "__AUL_PACKAGETYPE"
#define AUL_K_HWACC "__AUL_HWACC__"
#define AUL_K_APPID "__AUL_APPID__"
#define AUL_K_TASKMANAGE "__AUL_TASKMANAGE__"
#define AUL_K_APPID "__AUL_APPID__"
#define AUL_K_SDK "__AUL_SDK__"
#define AUL_K_ORG_CALLER_PID "__AUL_ORG_CALLER_PID__"
#define AUL_K_CALLER_PID "__AUL_CALLER_PID__"

#define SDK_CODE_COVERAGE "CODE_COVERAGE"
#define SDK_DEBUG "DEBUG"
#define SDK_DYNAMIC_ANALYSIS "DYNAMIC_ANALYSIS"
#define SDK_UNIT_TEST "UNIT_TEST"
#define SDK_VALGRIND "VALGRIND"
#define SDK_ATTACH "ATTACH"

/* DLP is short for debug-launchpad */
#define DLP_K_DEBUG_ARG "__DLP_DEBUG_ARG__"
#define DLP_K_UNIT_TEST_ARG "__DLP_UNIT_TEST_ARG__"
#define DLP_K_VALGRIND_ARG "__DLP_VALGRIND_ARG__"
#define DLP_K_ATTACH_ARG "__DLP_ATTACH_ARG__"

typedef struct {
	char *pkg_name;
	char *app_path;
	char *original_app_path;
	char *debug_appid;
	char *pkg_type;
	char *hwacc;
	char *taskmanage;
} appinfo_t;

appinfo_t *appinfo_create(bundle *kb);
void appinfo_free(appinfo_t *appinfo);
void modify_bundle(bundle *kb, int caller_pid, appinfo_t *appinfo, int cmd);

#endif /* __COMMON_H__ */
