/*
 * Copyright (c) 2017 Rockchip Electronics Co. Ltd.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#define LOG_TAG "echo_ringmic_test"
#include "common.h"

#define AUDIO_CHANNAL_CNT 8
#define FLAGS O_WRONLY | O_CREAT | O_TRUNC  
#define MODE S_IRWXU | S_IXGRP | S_IROTH | S_IXOTH 
#define RINGMIC_BAD_ERROR 93 /* has bad mic */

int *bytesToInt(char *src, int *length)
{
	int value = 0, offset = 0, i = 0;
	int *ret = NULL;
	int int_len = 0;

	int_len = (*length / 4) + 1;
	ret = (int *)malloc(int_len * 4);
	if (!ret)
		return NULL;

	while ((offset < *length) && (*length - offset >= 4)) {
		value = (int)((src[offset] & 0xFF) |
			      ((src[offset + 1] & 0xFF) << 8) |
			      ((src[offset + 2] & 0xFF) << 16) |
			      ((src[offset + 3] & 0xFF) << 24));
		offset += 4;
		ret[i++] = value;
	}

	*length = int_len;
	return ret;
}

int preProcessBuffer(void *data, void *out, int bytes)
{
	int i = 0, j = 0;

	for (i = 0; i < bytes / 2 ; ) {
		for (j = 0; j < AUDIO_CHANNAL_CNT; j++) {
			int tmp = 0;
			short tmp_data = (*((short *)data + i + j));
			tmp = ((tmp_data) << 16 | ((j+1) << 8)) & 0xffffff00;
			*((int *)out + i + j) = tmp;
		}
		i += AUDIO_CHANNAL_CNT;
	}

	return 0;
}

static int add_channel(char *src, char **dst, int len)
{
	int fd = 0;
	int dst_len = 0;
	int ret = 0;

	dst_len = len * 2;
	*dst = (char *)malloc(dst_len);
	if (!*dst)
		return -ENOMEM;

	preProcessBuffer(src, *dst, len);

	return dst_len;
}

int record_test(char *result)
{
	char cmd[128];
	char* error = NULL;
	int *record_ret = NULL;
	int fd = 0;
	int rf_len = 0; /* record file length */
	int pre_len = 0;
	char *rf_buff = NULL; /* record file buffer */
	char *pre_buff = NULL;
	int *buffer = NULL;
	int ret = 0;
	int i = 0;

	log_info("Start record test.\n");
	/*
	 * Play the specified file, and recording.
	 * recording at least 10 seconds.
	 */
	system("aplay /data/rectest_400hz.wav &");
	usleep(200000);
	system("arecord -t raw -D hw:1,0 -f S16_LE -c 8 -r 16000 -d 10 /data/ringmic_record.pcm &");

	log_info("Recording...\n");
	sleep(13);

	system("killall arecord");
	system("killall aplay");

	log_info("Parsing audio file...\n");
	fd = open("/data/ringmic_record.pcm", O_RDONLY);
	if (fd <= 0) {
		log_err("open /data/ringmic_record.pcm failed(%s)!\n",
			strerror(errno));
		return errno;
	}
	rf_len = lseek(fd, 0, SEEK_END);
	rf_buff = (char *)malloc(rf_len);
	if (!rf_buff) {
		close(fd);
		return -ENOMEM;
	}
	memset(rf_buff, 0, rf_len);
	lseek(fd, 0, SEEK_SET);
	ret = read(fd, rf_buff, rf_len);
	if (ret != rf_len) {
		log_err("read /data/ringmic_record.pcm failed!(%s)\n",
			strerror(errno));
		close(fd);
		free(rf_buff);
		return errno;
	}
	close(fd);

	/* Add channel numbers to the original recording file */
	pre_len = add_channel(rf_buff, &pre_buff, rf_len);
	if (pre_len < 0) {
		free(rf_buff);
		return pre_len;
	}
	free(rf_buff);

	buffer = bytesToInt(pre_buff, &pre_len);
	if (!buffer) {
		log_err("bytesToInt() failed!\n");
		free(pre_buff);
		return -ENOMEM;
	}
	free(pre_buff);
	record_ret = recordTestWr((int *)buffer, pre_len - 1280);
	printf("\n");
	for (i = 0; i < AUDIO_CHANNAL_CNT; i++) {
		if (*(record_ret + i)) {
			log_info("recordTest:#%d mic is bad!\n", i);
			*result++ = 1;
		} else {
			log_info("recordTest:#%d mic is ok!\n", i);
			*result++ = 0;
		}
	}

	system("rm -rf /data/ringmic_record.pcm");
	free(buffer);
	return 0;
}

int vibration_test(char *result)
{
	char cmd[128];
	char* error = NULL;
	int *record_ret = NULL;
	int fd = 0;
	int rf_len = 0; /* record file length */
	int pre_len = 0;
	char *rf_buff = NULL; /* record file buffer */
	char *pre_buff = NULL;
	int *buffer = NULL;
	int ret = 0;
	int i = 0;

	log_info("Start record test.\n");
	/*
	 * Play the specified file, and recording.
	 * recording at least 10 seconds.
	 */
	system("aplay /data/vibration.wav &");
	usleep(200000);
	system("arecord -t raw -D hw:1,0 -f S16_LE -c 8 -r 16000 /data/ringmic_vibration.pcm &");

	log_info("Recording...\n");
	sleep(13);

	system("killall arecord");
	system("killall aplay");

	log_info("Parsing audio file...\n");
	fd = open("/data/ringmic_vibration.pcm", O_RDONLY);
	if (fd <= 0) {
		log_err("open /data/ringmic_vibration.pcm failed(%s)!\n",
			strerror(errno));
		return errno;
	}
	rf_len = lseek(fd, 0, SEEK_END);
	rf_buff = (char *)malloc(rf_len);
	if (!rf_buff) {
		close(fd);
		return -ENOMEM;
	}
	memset(rf_buff, 0, rf_len);
	lseek(fd, 0, SEEK_SET);
	ret = read(fd, rf_buff, rf_len);
	if (ret != rf_len) {
		log_err("read /data/ringmic_vibration.pcm failed!(%s)\n",
			strerror(errno));
		close(fd);
		free(rf_buff);
		return errno;
	}
	close(fd);

	/* Add channel numbers to the original recording file */
	pre_len = add_channel(rf_buff, &pre_buff, rf_len);
	if (pre_len < 0) {
		free(rf_buff);
		return pre_len;
	}
	free(rf_buff);

	buffer = bytesToInt(pre_buff, &pre_len);
	if (!buffer) {
		log_err("bytesToInt() failed!\n");
		free(pre_buff);
		return -ENOMEM;
	}
	free(pre_buff);
	record_ret = vibrateTestWr((int *)buffer, pre_len - 1280);
	printf("\n");
	for (i = 0; i < AUDIO_CHANNAL_CNT; i++) {
		if (*(record_ret + i)) {
			log_info("vibrationTest:#%d mic is bad!\n", i);
			*result++ = 1;
		} else {
			log_info("vibrationTest:#%d mic is ok!\n", i);
			*result++ = 0;
		}
	}

	system("rm -rf /data/ringmic_vibration.pcm");
	free(buffer);
	return 0;
}

int main()
{
	char buf[COMMAND_VALUESIZE] = {0};
	char result[COMMAND_VALUESIZE] = RESULT_PASS;
	unsigned char record_ret[AUDIO_CHANNAL_CNT] = {0};
	unsigned char vibration_ret[AUDIO_CHANNAL_CNT] = {0};
	char *start = NULL;
	int ispass = 1;
	int i = 0, ret = 0;

	system("amixer set Playback 30%");

	start = buf;
	memcpy(start, "vibration:", strlen("vibration:"));
	start = start + strlen("vibration:");
	ret = vibration_test(vibration_ret);
	if (ret) {
		memcpy(start, "error", strlen("error"));
		start += strlen("error");
		ispass = 0;
	} else {
		for (i = 0; i < AUDIO_CHANNAL_CNT; i++) {
			if (vibration_ret[i]) {
				ispass = 0;
				*(start++) = '1' + i;
			}
		}
	}
	*start++ = ';';
	sleep(1);

	memcpy(start, "record:", strlen("record:"));
	start = start + strlen("record:");
	ret = record_test(record_ret);
	if (ret) {
		memcpy(start, "error", strlen("error"));
		start += strlen("error");
		strcpy(result, RESULT_FAIL);
		ispass = 0;
	} else {
		for (i = 0; i < AUDIO_CHANNAL_CNT; i++) {
			if (record_ret[i]) {
				ispass = 0;
				*(start++) = '1' + i;
			}
		}
	}
	*start++ = ';';

	if (!ispass) {
		strcpy(result, RESULT_FAIL);
		ret = -RINGMIC_BAD_ERROR;
	}

	send_msg_to_server(buf, result, ret);
	return 0;
}
