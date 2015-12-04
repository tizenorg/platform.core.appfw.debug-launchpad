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

#ifndef __COMMON_H__
#define __COMMON_H__

#define _GNU_SOURCE
#include <unistd.h>
#include <ctype.h>
#include <dlog.h>
#include <bundle.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "DEBUG_LAUNCHPAD"
#endif

#define _E(fmt, arg...) LOGE(fmt, ##arg)
#define _D(fmt, arg...) LOGD(fmt, ##arg)
#define _W(fmt, arg...) LOGW(fmt, ##arg)

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

#define SOCKET_PATH "/run/user"
#define MAX_LOCAL_BUFSZ 128
#define AUL_SOCK_MAXBUFF 65535

enum app_cmd {                                                                  
        APP_START,                                                              
        APP_OPEN,                                                               
        APP_RESUME,                                                             
        APP_RESUME_BY_PID,                                                      
        APP_TERM_BY_PID,                                                        
        APP_RESULT,                                                             
        APP_START_RES,                                                          
        APP_CANCEL,                                                             
        APP_KILL_BY_PID,                                                        
        APP_ADD_HISTORY,                                                        
        APP_RUNNING_INFO,                                                       
        APP_RUNNING_INFO_RESULT,                                                
        APP_IS_RUNNING,                                                         
        APP_GET_APPID_BYPID,                                                    
        APP_GET_APPID_BYPID_OK,                                                 
        APP_GET_APPID_BYPID_ERROR,                                              
        APP_KEY_EVENT,                                                          
        APP_KEY_RESERVE,                                                        
        APP_KEY_RELEASE,                                                        
        APP_STATUS_UPDATE,                                                      
        APP_RELEASED,                                                           
        APP_RUNNING_LIST_UPDATE                                                 
};            

typedef struct _app_pkt_t {
        int cmd;
        int len;
        unsigned char data[1];
} app_pkt_t;

typedef struct {
	char *appid;
	char *app_path;
	char *original_app_path;
	char *debug_appid;
	char *pkg_type;
	char *hwacc;
	char *taskmanage;
} appinfo_t;

int _create_server_sock(void);
app_pkt_t *_recv_pkt_raw(int fd, int *clifd, struct ucred *cr);
int _send_pkt_raw(int client_fd, app_pkt_t *pkt);

appinfo_t *_appinfo_create(bundle *kb);
void _appinfo_free(appinfo_t *appinfo);
void _modify_bundle(bundle *kb, int caller_pid, appinfo_t *appinfo, int cmd);

void _set_env(appinfo_t *app_info, bundle *kb);
char **_create_argc_argv(bundle *kb, int *margc, const char *app_path);

char *_proc_get_cmdline_bypid(int pid);

#endif /* __COMMON_H__ */
