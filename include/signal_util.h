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

#ifndef __SIGNAL_UTIL_H__
#define __SIGNAL_UTIL_H__

#include <sys/signalfd.h>

int _send_app_dead_signal(int dead_pid);
int _send_app_launch_signal(int launch_pid);
void _debug_launchpad_sigchld(struct signalfd_siginfo *info);
int _signal_init(void);
int _signal_get_sigchld_fd(void);
int _signal_unblock_sigchld(void);
int _signal_fini(void);

#endif /* __SIGNAL_UTIL_H__ */
