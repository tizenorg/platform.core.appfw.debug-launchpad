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

#include <sys/smack.h>
#include <sys/capability.h>

#include "security_util.h"

static struct __user_cap_header_struct h;
static struct __user_cap_data_struct inh_d[_LINUX_CAPABILITY_U32S_2];

extern int capset(cap_user_head_t hrdp, const cap_user_data_t datap);

int adjust_process_capability(int sv)
{
	switch (sv) {
	case CAPABILITY_GET_ORIGINAL;
		h.version = _LINUX_CAPABILITY_VERSION_2;
		h.pid = getpid();

		capget(&h, inh_d);

		inh_d[CAP_TO_INDEX(CAP_NET_RAW)].inheritable |= CAP_TO_MASK(CAP_NET_RAW);
		inh_d[CAP_TO_INDEX(CAP_SYS_CHROOT)].inheritable |= CAP_TO_MASK(CAP_SYS_CHROOT);
		break;
	case CAPABILITY_SET_INHERITABLE:
		h.pid = getpid();
		if (capset(&h, inh_d) < 0) {
			_E("Capability setting error");
			return -1;
		}
		break;
	default:
		break;
	}

	return 0;
}

int adjust_file_capability(const char *path)
{
	 if (cap_set_file(path, cap_from_text("CAP_NET_RAW,CAP_SYS_CHROOT+i"))) {
                _E("cap_set_file failed : %s", path);
                 return -1;
         }

	 return 0;
}

int set_smack_label(const char *path, const char *label)
{
	return smack_setlabel(path, label, SMACK_LABEL_ACCESS);
}
