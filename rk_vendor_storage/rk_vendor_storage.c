/*
 *  Copyright (c) 2017 Rockchip Electronics Co. Ltd.
 *  Author: Bin Yang <yangbin@rock-chips.com>
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
#include <arpa/inet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>

#define LOG_TAG "write_vendor"
#include "common.h"
#include "rk_vendor_storage.h"

int vendor_storage_read(int buf_size, uint8_t *buf, uint16_t vendor_id)
{
	int ret = 0;
	int fd;
	RK_VERDOR_REQ req;

	fd = open(VERDOR_DEVICE, O_RDWR, 0);
	if (fd < 0) {
		log_err("vendor_storage open fail, errno = %d\n", errno);
		return -1;
	}
	req.tag = VENDOR_REQ_TAG;
	req.id = vendor_id;
	req.len = buf_size > VENDOR_DATA_SIZE ? VENDOR_DATA_SIZE : buf_size;
	ret = ioctl(fd, VENDOR_READ_IO, &req);
	if (ret) {
		log_err("vendor read error, ret = %d\n", ret);
		close(fd);
		return -1;
	}
	close(fd);
	memcpy(buf, req.data, req.len);

	return 0;
}

int vendor_storage_write(int buf_size, uint8_t *buf, uint16_t vendor_id)
{
	int ret = 0;
	int fd;
	RK_VERDOR_REQ req;

	fd = open(VERDOR_DEVICE, O_RDWR, 0);
	if (fd < 0) {
		log_err("vendor_storage open fail, errno = %d\n", errno);
		return -1;
	}
	req.tag = VENDOR_REQ_TAG;
	req.id = vendor_id;
	req.len = buf_size > VENDOR_DATA_SIZE ? VENDOR_DATA_SIZE : buf_size;
	memcpy(req.data, buf, req.len);
	ret = ioctl(fd, VENDOR_WRITE_IO, &req);
	if(ret){
		log_err("vendor write error, ret = %d\n", ret);
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}

