/*
 *  write_storage.c  --  write storage application
 *
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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <errno.h>
#include <getopt.h>

#define LOG_TAG "write_storage"
#include "common.h"
#include "rk_vendor_storage.h"


#define UID_SIZE 20
#define LANMAC_SIZE 6
#define WIFIMAC_SIZE 6
#define BLUETOOTH_SIZE 0
#define TESTRESULT_SIZE 8

#define FACTORY_PARAM_FORMAT  "%s:%s"

typedef struct _PCBA_FACTORY_PARAMS {
	char name[COMMAND_VALUESIZE];
	char str[COMMAND_VALUESIZE];
	int size;
	int id;
} PCBA_FACTORY_PARAMS;

typedef enum _PARAMS_INDEX {
	INDEX_UID = 0,
	INDEX_LANMAC = 1,
	INDEX_WIFIMAC = 2,
	INDEX_BLUETOOTH = 3,
	INDEX_TESTRESULT = 4,
}PARAMS_INDEX;

PCBA_FACTORY_PARAMS g_pcba_params[] = {
	[INDEX_UID] = {
		.name = "UID",
		.size = UID_SIZE,
		.id = VENDOR_SN_ID,
	},
	[INDEX_LANMAC] = {
		.name = "LANMAC",
		.size = LANMAC_SIZE,
		.id = VENDOR_LAN_MAC_ID,
	},
	[INDEX_WIFIMAC] = {
		.name = "WIFIMAC",
		.size = WIFIMAC_SIZE,
		.id = VENDOR_WIFI_MAC_ID,
	},
	[INDEX_BLUETOOTH] = {
		.name = "BLUETOOTH",
		.size = BLUETOOTH_SIZE,
		.id = VENDOR_BLUETOOTH_ID,
	},
	[INDEX_TESTRESULT] = {
		.name = "TESTRESULT",
		.size = TESTRESULT_SIZE,
		.id = VENDOR_TESTRESULT_ID,
	},
};
#define FACTORY_PARAMS_NUM (sizeof(g_pcba_params) / sizeof(PCBA_FACTORY_PARAMS))

static char *msg_strupr(char *str)
{
	char *orign = str;

	for (; *str != '\0'; str++)
		*str = toupper(*str);

	return orign;
}

static int get_params_index(char *name)
{
	int index = 0;

	for(index = 0; index < FACTORY_PARAMS_NUM; index++) {
		if (!strcmp(name, g_pcba_params[index].name) || \
			!strcmp(msg_strupr(name), g_pcba_params[index].name))
			return  index;
	}

	return -1;
}

static int mac_addr_str_to_hex(char *mac_addr)
{
	int ret = 0;
	char mac_hex[6];

	ret = sscanf(mac_addr, "%2x%2x%2x%2x%2x%2x",
		mac_hex, mac_hex+1, mac_hex+2, mac_hex+3, mac_hex+4, mac_hex+5);
	if (ret != 6) {
		log_err("mac address (%s) format error\n", mac_addr);
		memset(mac_addr, 0, 6);
		return -1;
	}
	strcpy(mac_addr, mac_hex);

	return 0;
}

static int mac_addr_hex_to_str(char *mac_addr)
{
	char mac_str[COMMAND_VALUESIZE];

	snprintf(mac_str, sizeof(mac_str), "%2x%2x%2x%2x%2x%2x",
		mac_addr[0], mac_addr[1], mac_addr[2],
		mac_addr[3], mac_addr[4], mac_addr[5]);
	strcpy(mac_addr, mac_str);

	return 0;
}

static int get_msg_form_server(int argc, char **argv, char *str, int *prop_rw)
{
	int index = -1;
	int opt = 0;
	char *optstring = "s:g:v:S:G:V:";

	*prop_rw = -1;
	while ((opt = getopt(argc, argv, optstring)) != -1) {
		switch (opt) {
			case 's':
			case 'S':
				if ((index = get_params_index(optarg)) < 0)
					return -1;
				*prop_rw = 1;
			break;

			case 'g':
			case 'G':
				if ((index = get_params_index(optarg)) < 0)
					return -1;
				*prop_rw = 0;
			break;

			case 'v':
			case 'V':
				if (*prop_rw < 0)
					return -1;
				strcpy(str, optarg);
			break;

			default:
				return -1;
		}
	}

   return index;
}

int main(int argc, char **argv)
{
	int index = -1;
	int prop_rw = -1;
	int ret = 0;
	int err_code = 0;
	char buf[COMMAND_VALUESIZE];
	char result[COMMAND_VALUESIZE] = RESULT_PASS;
	char msg_buf[COMMAND_VALUESIZE];

	log_info("write vendor parameters...\n");
	memset(msg_buf, 0, sizeof(msg_buf));
	if ((index = get_msg_form_server(argc, argv, msg_buf, &prop_rw)) < 0) {
		log_err("get msg format fail\n");
		err_code = MSG_ERR;
		goto EXIT;
	}

	if (prop_rw < 0) {
		err_code = MSG_ERR;
		goto EXIT;
	} else if (prop_rw == 0) {
		goto READ_ONLY;
	}

	if ((index == INDEX_LANMAC) || (index == INDEX_WIFIMAC)) {
		ret = mac_addr_str_to_hex(msg_buf);
		if (ret) {
			err_code = MSG_ERR;
			goto EXIT;
		}
	}

	ret = vendor_storage_write(g_pcba_params[index].size,
		msg_buf, g_pcba_params[index].id);
	if (ret) {
		log_err("vendor storage write param fail, ret=%d\n", ret);
		err_code = WRITE_VENDOR_ERR;
		goto EXIT;
	}

READ_ONLY:
	ret = vendor_storage_read(g_pcba_params[index].size,
		msg_buf, g_pcba_params[index].id);
	if (ret) {
		log_err("vendor storage read uid fail, ret=%d\n", ret);
		err_code = READ_VENDOR_ERR;
		goto EXIT;
	}

	if ((index == INDEX_LANMAC) || (index == INDEX_WIFIMAC))
		mac_addr_hex_to_str(msg_buf);

	snprintf(buf, sizeof(buf), FACTORY_PARAM_FORMAT, g_pcba_params[index].name, msg_buf);

EXIT:
	if (err_code)
		strcpy(result, RESULT_FAIL);
	send_msg_to_server(buf, result, err_code);

	return err_code;
}
