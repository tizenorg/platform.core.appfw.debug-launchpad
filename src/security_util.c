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

#include <unistd.h>
#include <sys/types.h>
#include <sys/smack.h>
#include <security-manager.h>

#include "common.h"
#include "security_util.h"

int _set_smack_access_label(const char *path, const char *label)
{
	return smack_setlabel(path, label, SMACK_LABEL_ACCESS);
}

int _apply_smack_rules(const char *subject, const char *object,
		const char *access_type)
{
	int r;
	struct smack_accesses *rules = NULL;

	_D("%s %s %s", subject, object, access_type);

	r = smack_accesses_new(&rules);
	if (r != 0) {
		_E("smack_accesses_new() is failed.");
		return -1;
	}

	r = smack_accesses_add(rules, subject, object, access_type);
	if (r != 0) {
		_E("smack_accesses_add() is failed.");
		smack_accesses_free(rules);
		return -1;
	}

	r = smack_accesses_apply(rules);
	if (r != 0) {
		_E("smack_accesses_apply() is failed.");
		smack_accesses_free(rules);
		return -1;
	}

	smack_accesses_free(rules);

	return 0;
}

int _set_access(const char *appid)
{
	return security_manager_prepare_app(appid);
}
