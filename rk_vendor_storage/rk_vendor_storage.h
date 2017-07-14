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
 
#ifndef __RK_VENDOR_STORAGE__
#define __RK_VENDOR_STORAGE__
#define VERDOR_DEVICE "/dev/vendor_storage"

#define VENDOR_REQ_TAG	0x56524551
#define VENDOR_READ_IO	_IOW('v', 0x01, unsigned int)
#define VENDOR_WRITE_IO	_IOW('v', 0x02, unsigned int)

#define VENDOR_SN_ID		1
#define VENDOR_WIFI_MAC_ID	2
#define VENDOR_LAN_MAC_ID	3
#define VENDOR_BLUETOOTH_ID	4
#define VENDOR_TESTRESULT_ID 5


#define VENDOR_DATA_SIZE (3 * 1024)

typedef struct _RK_VERDOR_REQ {
	uint32_t tag;
	uint16_t id;
	uint16_t len;
	uint8_t data[VENDOR_DATA_SIZE];
} RK_VERDOR_REQ;

int vendor_storage_read(int buf_size, uint8_t *buf, uint16_t vendor_id);
int vendor_storage_write(int buf_size, uint8_t *buf, uint16_t vendor_id);

#endif

