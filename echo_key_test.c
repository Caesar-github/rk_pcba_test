/*
 *  key_test.c  --  key test application
 *
 *  Copyright (c) 2017 Rockchip Electronics Co. Ltd.
 *  Author: Bin Yang <yangbin@rock-chips.com>
 *  Author: Panzhenzhuan Wang <randy.wang@rock-chips.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <signal.h>

#define LOG_TAG "key_test"
#include "common.h"

#define KEY_INPUT_EVENT "/dev/input/event0"

#define KEY_TIMEOUT_DOWN	60
#define KEY_TIMEOUT_UP		5

#define KEY_QUERY_FAIL       -42

/*  key value */
#define KEY_DOWN_VAL	1
#define KEY_UP_VAL		2

/* key code */
#define KEY_UP_CODE		0
#define KEY_DOWN_CODE	0
#define KEY_OK_CODE		0
#define KEY_MODE_CODE	0
#define KEY_POWER_CODE	0
#define KEY_MENU_CODE	0
#define KEY_RESET_CODE	0
#define KEY_NUM_CODE	0
#define KEY_LOADER_CODE	1

static char result[COMMAND_VALUESIZE] = RESULT_FAIL;

static int key_wait_event(int maxfd, fd_set *readfds, int time)
{
	int ret;
	struct timeval timeout;

	FD_ZERO(readfds);
	FD_SET(maxfd, readfds);
	timeout.tv_sec = time;
	timeout.tv_usec = 0;
	ret = select(maxfd + 1, readfds, NULL, NULL, &timeout);
	switch (ret) {
		case -1:
			return -1;
		case 0:
			log_err("select timeout(%ds)\n", time);
			return 1;
		default:
			if (FD_ISSET(maxfd, readfds)) {
				FD_CLR (maxfd, readfds);
				return 0;
			}
			break;
	}

	return -1;
}

static int key_event_read(int fd, struct input_event *buf)
{
	int read_len = 0;

	read_len = read(fd, buf, sizeof(*buf));
	if (read_len < 0) {
		if ((errno != EINTR) && (errno != EAGAIN))
			return 0;
		return -1;
	}

	if (buf->type)
		return 1;

	return 0;
}

//* 信号处理函数，在结束进程前，为按键测试返回一个结果；
static int key_result_send(int sign_no)
{
    int err_code =0;
    printf("====================function : %s start =================\n",__func__);
    if(!memcmp(result,RESULT_FAIL,strlen(RESULT_FAIL))){
        err_code = KEY_QUERY_FAIL;
    }
    send_msg_to_server("key_test", result, err_code);

    printf("====================function : %s finished =================\n",__func__);
    exit(0);
}

int main(int argc, char **argv)
{
	int fd;
	int ret = 0;
	int err_code = 0;
	int time = KEY_TIMEOUT_DOWN;
	fd_set rdfds;
	struct input_event key_event;
	int modifier;
	char buf[COMMAND_VALUESIZE] = {0};

	log_info("key test process start...\n");
    //* 注册信号处理函数
	signal(SIGTERM,key_result_send);

	fd = open(KEY_INPUT_EVENT, O_RDONLY | O_NOCTTY);
	if (fd < 0) {
		log_err("open fail:%s\n", strerror(errno));
		err_code = KEY_OPEN_FAIL;
		goto EXIT;
	}

	while (1) {
		if (key_wait_event(fd, &rdfds, time) == 0) {
			ret = key_event_read(fd, &key_event);
			if (ret > 0) {
				if (key_event.value) {
					log_info("key(%d) is down\n", key_event.code);
					time = KEY_TIMEOUT_UP;
				} else {
					log_info("key(%d) is up\n", key_event.code);
					time = KEY_TIMEOUT_DOWN;
					strcpy(result, RESULT_VERIFY);
					break;
				}
			}
		} else {
			log_err("wait key event fail, errno=%d\n", errno);
			err_code = KEY_EVENT_TIMEOUT;
			goto EXIT;
		}
	}
	snprintf(buf, sizeof(buf), "key_code:%d", key_event.code);

EXIT:
	if (!err_code)
		strcpy(result, RESULT_VERIFY);
	send_msg_to_server(buf, result, err_code);

	return err_code;
}

