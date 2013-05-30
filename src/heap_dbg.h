/*
 *  aul
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>, Jaeho Lee <jaeho81.lee@samsung.com>
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


#include <malloc.h>
#include <stdio.h>
#include <signal.h>

#ifdef HEAPDGB_ACTIVATE

#define HOOK_RESET()	\
do {\
	__malloc_hook = old_malloc_hook; \
	__free_hook = old_free_hook;	\
} while (0);

#define HOOK_SET()	\
do {\
	__malloc_hook = my_malloc;	\
	__free_hook = my_free;		\
} while (0);

static void *(*old_malloc_hook) (size_t size, const void *caller);
static void *(*old_realloc_hook) (void *ptr, size_t size, const void *caller);
static void (*old_free_hook) (void *ptr, const void *caller);

static void *my_malloc(size_t size, const void *caller);
static void *my_realloc(void *ptr, size_t size, const void *caller);
static void my_free(void *ptr, const void *caller);

static void my_free(void *ptr, const void *caller)
{
	void *callstack_addrs[20];
	char **callstack_strings;
	int i;

	HOOK_RESET();

	printf("%c[1;31m[FREE] %x %x", 27, ptr, caller);
	printf("%c[0m\n", 27);
	free(ptr);

	HOOK_SET();

}

static void *my_malloc(size_t size, const void *caller)
{
	void *ptr;

	HOOK_RESET();

	ptr = malloc(size);
	printf("%c[1;31m[MALLOC] %x %x", 27, ptr, caller);
	printf("%c[0m\n", 27);

	HOOK_SET();

	return ptr;
}

static void malloc_init(void)
{
	old_malloc_hook = __malloc_hook;
	old_free_hook = __free_hook;

	HOOK_SET();
}

__attribute__ ((visibility("default")))
void (*__malloc_initialize_hook) (void) = malloc_init;

#else

#endif
