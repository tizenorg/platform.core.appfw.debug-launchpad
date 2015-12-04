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

#ifndef __SECURITY_UTIL_H__
#define __SECURITY_UTIL_H__

#define CAPABILITY_GET_ORIGINAL 0
#define CAPABILITY_SET_INHERITABLE 1

int _adjust_process_capability(int sv);
int _adjust_file_capability(const char *path);
int _set_smack_label(const char *path, const char *label);
int _apply_smack_rules(const char *subject, const char *object, const char *access_type);

#endif /* __SECURITY_UTIL_H__ */
