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

#ifndef __DEBUG_UTIL_H__
#define __DEBUG_UTIL_H__

#include <stdbool.h>
#include <bundle.h>

bool _gdbserver_is_running(void);
int _get_gdbserver_pid(void);
int _get_gdbserver_app_pid(void);
int _get_valgrind_option(void);
int _prepare_debug_tool(bundle *kb, const char *appid, const char **str_arr,
		int len);
void _change_file(const char *path);
void _wait_for_valgrind_output(void);
void _set_env(appinfo_t *app_info, bundle *kb);
char **_create_argc_argv(bundle *kb, int *margc, const char *app_path);

#endif /* __DEBUG_UTIL_H__ */

