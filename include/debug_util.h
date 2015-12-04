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

#ifndef __DEBUG_UTIL_H__
#define __DEBUG_UTIL_H__

#include <stdbool.h>
#include <bundle.h>

#define OPT_VALGRIND_LOGFILE_FIXED "--log-file=/tmp/valgrind_result.txt"
#define OPT_VALGRIND_XMLFILE_FIXED "--xml-file=/tmp/valgrind_result.xml"
#define OPT_VALGRIND_MASSIFFILE_FIXED "--massif-out-file=/tmp/valgrind_result.xml"
#define PATH_VALGRIND_LOGFILE "/tmp/valgrind_result.txt"
#define PATH_VALGRIND_XMLFILE "/tmp/valgrind_result.xml"
#define PATH_VALGRIND_MASSIFFILE PATH_VALGRIND_XMLFILE

bool gdbserver_is_running(void);
int get_gdbserver_pid(void);
int get_gdbserver_app_pid(void);
int get_valgrind_option(void);
int prepare_debug_tool(bundle *kb, const char *appid, const char **str_arr, int len);
void change_file(const char *path);
void wait_for_valgrind_output(void);
void set_env(appinfo_t *app_info, bundle *kb);
char **create_argc_argv(bundle *kb, int *margc, const char *app_path);

#endif /* __DEBUG_UTIL_H__ */
