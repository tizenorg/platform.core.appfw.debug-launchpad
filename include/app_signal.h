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


#ifndef __APP_DBUS_H__
#define __APP_DBUS_H__

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

#define AUL_DBUS_PATH "/aul/dbus_handler"
#define AUL_DBUS_SIGNAL_INTERFACE "org.tizen.aul.signal"
#define AUL_DBUS_APPDEAD_SIGNAL	"app_dead"
#define AUL_DBUS_APPLAUNCH_SIGNAL	"app_launch"

#define OPT_VALGRIND_LOGFILE		"--log-file="
#define OPT_VALGRIND_LOGFILE_FIXED	"--log-file=/tmp/valgrind_result.txt"
#define PATH_VALGRIND_LOGFILE		"/tmp/valgrind_result.txt"
#define OPT_VALGRIND_XMLFILE		"--xml-file="
#define OPT_VALGRIND_XMLFILE_FIXED	"--xml-file=/tmp/valgrind_result.xml"
#define PATH_VALGRIND_XMLFILE		"/tmp/valgrind_result.xml"
#define OPT_VALGRIND_MASSIFFILE		"--massif-out-file="
#define OPT_VALGRIND_MASSIFFILE_FIXED	"--massif-out-file=/tmp/valgrind_result.xml"

#endif
