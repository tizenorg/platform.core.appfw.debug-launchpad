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

#ifndef __DEFS_H__
#define __DEFS_H__

#define AUL_K_STARTTIME "__AUL_STARTTIME__"
#define AUL_K_EXEC "__AUL_EXEC__"
#define AUL_K_PACKAGETYPE "__AUL_PACKAGETYPE__"
#define AUL_K_HWACC "__AUL_HWACC__"
#define AUL_K_APPID "__AUL_APPID__"
#define AUL_K_PID "__AUL_PID__"
#define AUL_K_TASKMANAGE "__AUL_TASKMANAGE__"
#define AUL_K_INTERNAL_POOL "__AUL_INTERNAL_POOL__"
#define AUL_K_PKGID "__AUL_PKGID_"
#define AUL_K_DEBUG "__AUL_DEBUG__"
#define AUL_K_SDK "__AUL_SDK__"
#define AUL_K_ORG_CALLER_PID "__AUL_ORG_CALLER_PID__"
#define AUL_K_CALLER_PID "__AUL_CALLER_PID__"
#define AUL_K_COMP_TYPE "__AUL_COMP_TYPE__"
#define AUL_K_PRIVACY_APPID "__AUL_PRIVACY_APPID__"

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
#define DLP_K_GDBSERVER_PATH "__DLP_GDBSERVER_PATH__"
#define DLP_K_VALGRIND_PATH "__DLP_VALGRIND_PATH__"

#define PATH_DA_SO "/home/developer/sdk_tools/da/da_probe.so"

#define OPT_VALGRIND_LOGFILE_FIXED "--log-file=/tmp/valgrind_result.txt"
#define OPT_VALGRIND_XMLFILE_FIXED "--xml-file=/tmp/valgrind_result.xml"
#define OPT_VALGRIND_MASSIFFILE_FIXED \
	"--massif-out-file=/tmp/valgrind_result.xml"
#define PATH_VALGRIND_LOGFILE "/tmp/valgrind_result.txt"
#define PATH_VALGRIND_XMLFILE "/tmp/valgrind_result.xml"
#define PATH_VALGRIND_MASSIFFILE PATH_VALGRIND_XMLFILE

#endif /* __DEFS_H__ */

