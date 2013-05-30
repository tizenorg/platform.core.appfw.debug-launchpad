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


#include <ail.h>
#include <string.h>
#include <stdio.h>
#include "simple_util.h"

#define MAX_PATH_LEN	1024

#define AUL_APP_INFO_FLD_PKG_NAME		"package"
#define AUL_APP_INFO_FLD_APP_PATH		"exec"
#define AUL_APP_INFO_FLD_APP_TYPE		"x_slp_packagetype"
#define AUL_APP_INFO_FLD_WIDTH			"x_slp_baselayoutwidth"
#define AUL_APP_INFO_FLD_HEIGHT			"x_slp_baselayoutheight"
#define AUL_APP_INFO_FLD_VERTICAL		"x_slp_ishorizontalscale"
#define AUL_APP_INFO_FLD_MULTIPLE		"x_slp_multiple"
#define AUL_APP_INFO_FLD_TASK_MANAGE	"x_slp_taskmanage"
#define AUL_APP_INFO_FLD_MIMETYPE		"mimetype"
#define AUL_APP_INFO_FLD_SERVICE		"x_slp_service"

#define AUL_RETRIEVE_PKG_NAME			"package = '?'"
#define AUL_RETRIEVE_APP_PATH			"exec = '?'"
#define AUL_RETRIEVE_MIMETYPE			"mimetype like '?'"
#define AUL_RETRIEVE_SERVICE			"x_slp_service like '?'"

typedef struct {
	char *pkg_name;		/* package */
	char *app_path;		/* exec */
	char *original_app_path;	/* exec */
	char *pkg_type;		/* x_slp_packagetype */
	char *hwacc;		/* hwacceleration */
} app_info_from_db;

static inline char *_get_pkgname(app_info_from_db *menu_info)
{
	return menu_info ? menu_info->pkg_name : NULL;
}

static inline char *_get_app_path(app_info_from_db *menu_info)
{
	int i = 0;
	int path_len = -1;

	if (!menu_info || menu_info->app_path == NULL)
		return NULL;

	while (menu_info->app_path[i] != 0) {
		if (menu_info->app_path[i] == ' '
		    || menu_info->app_path[i] == '\t') {
			path_len = i;
			break;
		}
		i++;
	}

	if (path_len == 0) {
		free(menu_info->app_path);
		menu_info->app_path = NULL;
	} else if (path_len > 0) {
		char *tmp_app_path = malloc(sizeof(char) * (path_len + 1));
		if(tmp_app_path == NULL)
			return NULL;
		snprintf(tmp_app_path, path_len + 1, "%s", menu_info->app_path);
		free(menu_info->app_path);
		menu_info->app_path = tmp_app_path;
	}

	return menu_info->app_path;
}

static inline char *_get_original_app_path(app_info_from_db *menu_info)
{
	return menu_info ? menu_info->original_app_path : NULL;
}

static inline void _free_app_info_from_db(app_info_from_db *menu_info)
{
	if (menu_info != NULL) {
		if (menu_info->pkg_name != NULL)
			free(menu_info->pkg_name);
		if (menu_info->app_path != NULL)
			free(menu_info->app_path);
		if (menu_info->original_app_path != NULL)
			free(menu_info->original_app_path);
		if (menu_info->hwacc != NULL)
			free(menu_info->hwacc);
		free(menu_info);
	}
}

static inline app_info_from_db *_get_app_info_from_db_by_pkgname(
							const char *pkgname)
{
	app_info_from_db *menu_info;
	ail_appinfo_h handle;
	ail_error_e ret;
	char *str = NULL;

	menu_info = calloc(1, sizeof(app_info_from_db));
	if (menu_info == NULL) {
		return NULL;
	}

	ret = ail_get_appinfo(pkgname, &handle);
	if (ret != AIL_ERROR_OK) {
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	ret = ail_appinfo_get_str(handle, AIL_PROP_PACKAGE_STR, &str);
	if (str) {
		menu_info->pkg_name = strdup(str);	
		str = NULL;
	}

	ret = ail_appinfo_get_str(handle, AIL_PROP_EXEC_STR, &str);
	if (str) {
		menu_info->app_path = strdup(str);
		str = NULL;
	}

	if (menu_info->app_path != NULL)
		menu_info->original_app_path = strdup(menu_info->app_path);

	ret = ail_appinfo_get_str(handle, AIL_PROP_X_SLP_PACKAGETYPE_STR, &str);
	if (str) {
		menu_info->pkg_type = strdup(str);
		str = NULL;
	}
	
	ret = ail_destroy_appinfo(handle);
	if (ret != AIL_ERROR_OK) {
		_E("ail_destroy_appinfo failed");
	}

	if (!_get_app_path(menu_info)) {
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	return menu_info;
}

static inline ail_cb_ret_e __appinfo_func(const ail_appinfo_h appinfo, void *user_data)
{
	app_info_from_db *menu_info = (app_info_from_db *)user_data;
	char *package;
	ail_cb_ret_e ret = AIL_CB_RET_CONTINUE;

	if (!menu_info)
		return ret;

	ail_appinfo_get_str(appinfo, AIL_PROP_PACKAGE_STR, &package);
	if (package) {
		menu_info->pkg_name = strdup(package);
		ret = AIL_CB_RET_CANCEL;
	}

	return ret;
}

static inline app_info_from_db *_get_app_info_from_db_by_apppath(
							const char *apppath)
{
	app_info_from_db *menu_info = NULL;
	ail_filter_h filter;
	ail_error_e ret;
	int count;
	
	if (apppath == NULL)
		return NULL;

	menu_info = calloc(1, sizeof(app_info_from_db));
	if (menu_info == NULL)
		return NULL;

	ret = ail_filter_new(&filter);
	if (ret != AIL_ERROR_OK) {
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	ret = ail_filter_add_str(filter, AIL_PROP_X_SLP_EXE_PATH, apppath);
	if (ret != AIL_ERROR_OK) {
		ail_filter_destroy(filter);
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	ret = ail_filter_count_appinfo(filter, &count);
	if (ret != AIL_ERROR_OK) {
		ail_filter_destroy(filter);
		_free_app_info_from_db(menu_info);
		return NULL;
	}
	if (count < 1) {
		ail_filter_destroy(filter);
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	ail_filter_list_appinfo_foreach(filter, __appinfo_func, (void *)menu_info);

	ail_filter_destroy(filter);

	menu_info->app_path = strdup(apppath);
	menu_info->original_app_path = strdup(apppath);

	return menu_info;
	
}

