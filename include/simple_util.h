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


#ifndef __SIMPLE_UTIL__
#define __SIMPLE_UTIL__

#include <unistd.h>
#include <ctype.h>
#include <dlog.h>

#ifdef LAUNCHPAD_LOG
#undef LOG_TAG
#define LOG_TAG "AUL_PAD"
#else
#undef LOG_TAG
#define LOG_TAG "AUL"
#endif
#ifdef AMD_LOG
#undef LOG_TAG
#define LOG_TAG "AUL_AMD"
#endif


#define MAX_LOCAL_BUFSZ 128
#define MAX_PID_STR_BUFSZ 20

#define _E(fmt, arg...) LOGE(fmt, ##arg)
#define _D(fmt, arg...) LOGD(fmt, ##arg)
#define _W(fmt, arg...) LOGW(fmt, ##arg)

#define retvm_if(expr, val, fmt, arg...) do { \
	if (expr) { \
		_E(fmt, ##arg); \
		_E("(%s) -> %s() return", #expr, __FUNCTION__); \
		return (val); \
	} \
} while (0)

#define retv_if(expr, val) do { \
	if (expr) { \
		_E("(%s) -> %s() return", #expr, __FUNCTION__); \
		return (val); \
	} \
} while (0)

int __proc_iter_cmdline(int (*iterfunc)
			 (const char *dname, const char *cmdline, void *priv),
			void *priv);
int __proc_iter_pgid(int pgid, int (*iterfunc) (int pid, void *priv),
		     void *priv);
char *__proc_get_cmdline_bypid(int pid);

static inline const char *FILENAME(const char *filename)
{
	const char *p;
	const char *r;

	if (!filename)
		return NULL;

	r = p = filename;
	while (*p) {
		if (*p == '/')
			r = p + 1;
		p++;
	}

	return r;
}

#endif
