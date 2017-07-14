/*
 *  pcbatest_server.c  --  pcba test application
 *
 *  Copyright (c) 2017 Rockchip Electronics Co. Ltd.
 *  Author: Bin Yang <yangbin@rock-chips.com>
 *  Modified by Panzhenzhuan Wang <randy.wang@rock-chips.com> for rk3036-echo
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
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <linux/watchdog.h>

#include <unistd.h>

#define LOG_TAG "pcbatest_server"
#include "common.h"
#include "pcbatest_server.h"
#include "cJSON.h"

#define PARENT_EXIT 0
#define CHILD_EXIT 1
#define FORK_FAIL -1

static void sig_child_handle(int sig)
{
	int status = 0;
	pid_t pid;

	if (sig == SIGCHLD)
		while((pid = waitpid(-1, &status, WNOHANG)) > 0);
}

static int disable_wdt(void)
{
	int fd = 0;

	fd = open(DEV_WDT_NAME, O_WRONLY);
	if (fd == -1) {
		log_err ("%s open error\n", DEV_WDT_NAME);
	} else {
		write(fd , "V", 1);
		close(fd);
	}

	return 0;
}

static int run_cmd_to_shell(char* cmd)
{
	int ret = 0;
	int read_len = 0;
	FILE* read_fp;
	char buf[COMMAND_VALUESIZE] = {0};

	read_fp = popen(cmd, "r");
	if (read_fp != NULL) {
		read_len = fread(buf, sizeof(char), sizeof(buf), read_fp);
		if (read_len > 0)
			ret = 0;
		else
			ret = -1;
		pclose(read_fp);
	} else {
		ret = -1;
	}

	return ret;
}

static int run_cmd_to_shell_duplex(char *cmd, char *w_buf, char *r_buf, char *match_str)
{
	int ret = 0;
	int read_len = 0;
	FILE *fp;
	char buf[COMMAND_VALUESIZE] = {0};
	char cmd_msg[COMMAND_VALUESIZE] = {0};

	snprintf(cmd_msg, sizeof(cmd_msg),"%s  %s\0", cmd, w_buf);
	log_info("========cmd_msg is : %s\n",cmd_msg);

	fp = popen(cmd_msg, "r");
	if (fp == NULL) {
		log_err("run_cmd_to_shell_duplex dpopen fail, errno=%d\n", errno);
		return -1;
	}

	if(match_str == NULL){
		read_len = fread(buf, sizeof(char), sizeof(buf), fp);
		if (read_len <= 0)
			ret = -1;
	} else {
		while (fgets(buf, sizeof(buf), fp)) {
			if (strstr(buf, match_str)) {
			    log_info("====================================\n");
                log_info("strstr(buf, match_str) is : %s\n",buf);
				strcpy(r_buf, buf);
				break;   //* 新添加
			} else {
				puts(buf);
			}
		}
	}

EXIT:
	pclose(fp);
	return ret;
}

static int process_is_exists(char *process_name)
{
	FILE *fp;
	char cmd[COMMAND_VALUESIZE] = {0};
	char buf[COMMAND_VALUESIZE] = {0};

	snprintf(cmd, sizeof(cmd), "ps | grep %s | grep -v grep\0", process_name);
	fp = popen(cmd, "r");
	if (!fp) {
		log_err("popen ps | grep %s fail\n", process_name);
		return -1;
	}
	while (fgets(buf, sizeof(buf), fp)) {
		if (strstr(buf, process_name)) {
			fclose(fp);
			return 1;
		}
	}
	fclose(fp);
	return 0;
}

static int pcba_test_result_rw(PCBA_SINGLE_PARA *recv_paras, char *w_buf, char *r_buf, bool rw)
{
	int ret = 0;
	int fd = -1;
	char pcbatest_result_filename[COMMAND_VALUESIZE] = {0};

	snprintf(pcbatest_result_filename, sizeof(pcbatest_result_filename),
		"%s/%s_result\0", TEST_RESULT_SAVE_PATH,
		recv_paras[INDEX_TEST_ITEM].valuestr);

	if (rw) {
        log_info("=================fucntion: %s================\n",__func__);
		log_info("write result ** pcbatest_result_filename is :%s\n",pcbatest_result_filename);
        if(w_buf[0]!='\0'){
            fd = open(pcbatest_result_filename, O_CREAT | O_WRONLY	| O_TRUNC);
            if (fd < 0)
            {
                log_err("open %s fail, errno = %d\n", pcbatest_result_filename, errno);
                return -1;
            }
            write(fd, w_buf, COMMAND_VALUESIZE);
        }
        else {
            log_info("w_buf is NUll, do nothing\n");
        }
	} else {
		fd = open(pcbatest_result_filename, O_RDONLY);
		if (fd < 0) {
			log_info("can't open %s, errno = %d\n", pcbatest_result_filename, errno);
			return 1;
		}
		ret = read(fd, r_buf, COMMAND_VALUESIZE);
		if (ret <= 0) {
			log_err("read %s fail, errno = %d\n", pcbatest_result_filename, errno);
			ret = -1;
		}
		log_info("\n**********Read file: %s; Result is %s\t*****\n",pcbatest_result_filename,r_buf);
	}
	close(fd);

	return ret;
}

static int pcba_stop_process(char *process, char *str)
{
	int count = 0;

	while (process_is_exists(process) > 0) {
		log_info("stop %s... \n", process);
		system(str);
		sleep(1);
		count++;
		if (count > 3)
			return -1;
	}
	return 0;
}

static int pcba_start_process(char *process, char *str)
{
	if (process_is_exists(process) > 0) {
		log_err("process %s already exists \n", process);
		return -1;
	}
	system(str);
	return 0;
}

static int enter_pcba_test_mode(PCBA_SINGLE_PARA *recv_paras, char *test_flag)
{
	int ret = 0;

	log_info("enter pcba test mode ...\n");

	/*Kill wakeWordAgent process before pcba test*/
	//new added
	//system(" kill `ps | grep wakeWordAgent| grep -v grep | awk '{print $1}'`");
	system("close_wakeWord.sh");
	*test_flag = 1;

	return 0;
}

static int exit_pcba_test_mode(PCBA_SINGLE_PARA *recv_paras, char *test_flag)
{
	int ret = 0;
	DIR *dir = NULL;
	struct dirent *dir_ptr = NULL;
	char pcbatest_result_filename[COMMAND_VALUESIZE] = {0};

	if ((dir = opendir(TEST_RESULT_SAVE_PATH)) == NULL) {
		log_err("exit test mode opendir fail\n");
		return EXIT_TEST_ERR;
	}
	while ((dir_ptr = readdir(dir)) != NULL) {
		if (strstr(dir_ptr->d_name, "_result")) {
			snprintf(pcbatest_result_filename, COMMAND_VALUESIZE, "%s/%s",
				TEST_RESULT_SAVE_PATH, dir_ptr->d_name);
			remove(pcbatest_result_filename);
		}
	}
	closedir(dir);
	if (ret)
		return EXIT_TEST_ERR;
	*test_flag = 0;

    /*Restart wakeWordAgent when finished pcba test*/
    //new added
    //system("/data/wakeWordAgent -e gpio &");
    system("restart_wakeWord.sh");

	return 0;
}

static int pcba_test_item_process(PCBA_SINGLE_PARA *recv_paras)
{
	int ret;
	int fd;
	char buf[COMMAND_VALUESIZE] = {0};
	char pcba_test_filename[COMMAND_VALUESIZE] = {0};

	/*snprintf(pcba_test_filename, sizeof(pcba_test_filename),
		"%s/%s\0", PCBA_TEST_PATH,
		recv_paras[INDEX_TEST_ITEM].valuestr);
		*/
    /*snprintf(pcba_test_filename, sizeof(pcba_test_filename),
		"%s\0",recv_paras[INDEX_TEST_ITEM].valuestr);*/

    strcpy(pcba_test_filename,recv_paras[INDEX_TEST_ITEM].valuestr);

	chmod(pcba_test_filename, S_IRUSR|S_IWUSR|S_IXUSR);

	ret = run_cmd_to_shell_duplex(pcba_test_filename,
		recv_paras[INDEX_MSG].valuestr, buf, TESTITEM_SEND_HEAD);
	if (ret) {
		log_err("run_cmd_to_shell_duplex fail, ret=%d \n", ret);
		return TEST_FORK_ERR;
	}

	log_info("pcba_test_result_rw buf is : %s\n",buf);
	ret = pcba_test_result_rw(recv_paras, buf, NULL, 1);
	if (ret)
		return SAVE_RESULE_ERR;

	return ret;
}

static int start_pcba_test_proccess(PCBA_SINGLE_PARA *recv_paras, int *err_code)
{
	int ret = 0;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		log_err("fork send_command error\n");
		return FORK_FAIL;
	} else if (0 == pid) {
	    log_info(" ********I am child :%d\t**********\n",getpid());
		if (ret = pcba_test_item_process(recv_paras))
			log_err("test item process fail, ret=%d\n", ret);
		*err_code = ret;
		return CHILD_EXIT;
	}

	return PARENT_EXIT;
}

static int start_pcba_test_preproccess(PCBA_SINGLE_PARA *recv_paras, int test_flag)
{
	int ret = 0;
	char pcbatest_result_filename[COMMAND_VALUESIZE] = {0};

	if (!test_flag) {
		log_err("not enter pcba test mode \n");
		ret = TEST_MODE_ERR;
	}

	snprintf(pcbatest_result_filename, sizeof(pcbatest_result_filename),
		"%s/%s_result\0", TEST_RESULT_SAVE_PATH,
		recv_paras[INDEX_TEST_ITEM].valuestr);
	if (access(pcbatest_result_filename, F_OK) == 0)
		remove(pcbatest_result_filename);

	if (process_is_exists(recv_paras[INDEX_TEST_ITEM].valuestr)) {
		log_err("start test fail, test item %s already exists\n",
			recv_paras[INDEX_TEST_ITEM].valuestr);
		ret = TEST_ITEM_BUSY;
	}

	return ret;
}

static int stop_pcba_test(PCBA_SINGLE_PARA *recv_paras)
{
	int count = 0;
	char pcbatest_result_filename[COMMAND_VALUESIZE] = {0};
	char test_item_process[COMMAND_VALUESIZE] = {0};

	snprintf(pcbatest_result_filename, sizeof(pcbatest_result_filename),
		"%s/%s_result\0", TEST_RESULT_SAVE_PATH,
		recv_paras[INDEX_TEST_ITEM].valuestr);
	if (access(pcbatest_result_filename, F_OK) == 0){
            //remove(pcbatest_result_filename);
	}

	while (process_is_exists(recv_paras[INDEX_TEST_ITEM].valuestr) > 0) {
		log_info("kill %s ...\n", recv_paras[INDEX_TEST_ITEM].valuestr);
		snprintf(test_item_process, sizeof(test_item_process),
			"busybox killall %s\0", recv_paras[INDEX_TEST_ITEM].valuestr);
		run_cmd_to_shell(test_item_process);
		sleep(1);
		count++;
		if (count > 3)
			return STOP_TEST_ERR;
	}

	return 0;
}

static int query_test_result(PCBA_SINGLE_PARA *recv_paras, char *msg, char *result, int *err_code)
{
	int ret = 0;
	int fd;
	int err = 0;
	char buf[COMMAND_VALUESIZE];

	*err_code =  0;
	ret = pcba_test_result_rw(recv_paras, NULL, buf, 0);

    //添加循环查询测试结果使用
    //ret = 1;

	if (ret == 1) {
		strcpy(result, RESULT_TESTING);
		return 0;
	} else if (ret == -1) {
	    log_info("==========function :\t %s==line :\t%d====\n",__func__,__LINE__);
		return QUERY_RESULT_ERR;
	}
	ret = sscanf(buf, TESTITEM_SEND_PARSE, msg, result, &err);
	log_info("***************ret= is: %d\n",ret);
	if (ret != 3) {
		ret = sscanf(buf, TESTITEM_SEND_PARSE_NOMSG, result, &err);
		if (ret != 2) {
			log_err("pcbatest result query fail, msg:%s, result:%s, err_code:%d, ret=%d\n",
				msg, result, err, ret);
//            log_info("==========function :\t %s==line :\t%d====\n",__func__,__LINE__);
//            strcpy(result, RESULT_TESTING);
//            return 0;
			return QUERY_RESULT_ERR;
		}
	}
	*err_code =  err;

	return 0;
}

static int tcp_command_check(PCBA_COMMAND_FORMAT index, char *str)
{
	int num = 0;
	char pcba_test_filename[COMMAND_VALUESIZE] = {0};
	struct stat file_stat;

	switch (index) {
	case INDEX_TYPE:
		if (strcmp(str, RECV_TYPE_NAME)) {
			log_err("not found type (%s) is error type\n", str);
			return CMD_TYPE_ERR;
		}
		break;

	case INDEX_TEST_ITEM:
		/*snprintf(pcba_test_filename, sizeof(pcba_test_filename),
			"%s/%s\0", PCBA_TEST_PATH, str);*/

        snprintf(pcba_test_filename, sizeof(pcba_test_filename),"%s\0",str);

		/*if (access(pcba_test_filename, F_OK)) {
			log_err("not found test item(%s), re-download file\n", pcba_test_filename);
			return TEST_ITEM_ERR;
		} else if (stat(pcba_test_filename, &file_stat) == 0) {
			if (file_stat.st_mode & S_IFDIR) {
				log_err("test_item error %s is directory\n", pcba_test_filename);
				return TEST_ITEM_ERR;
			}
		}*/
		break;

	case INDEX_CMD:
		for (num = 0; num < RECV_CMD_NUM; num++ ) {
			if (!strcmp(str, recv_cmd_type[num].name))
				break;
		}
		if (num == RECV_CMD_NUM) {
			log_err("not found command (%s) is error command.\n", str);
			return CMD_ERR;
		}
		break;

	case INDEX_MSG:
		break;

	default:
		return RECV_FORMAT_ERR;
	}

	return CMD_CHK_OK;
}

static void tcp_command_fill(PCBA_COMMAND_PARA *cmd_paras, char *status, char *msg,
	char *result, int err_code)
{
	int num = 0;
	char str_err_code[20];
	bool *opt;
	bool send_para_optional[SEND_COMMAND_PARANUM];
	PCBA_SINGLE_PARA *recv_paras = cmd_paras->recv_paras;
	PCBA_SINGLE_PARA *send_paras = cmd_paras->send_paras;

	for (num = 0; num < SEND_COMMAND_PARANUM; num++)
		send_para_optional[num] = false;

	if ((!strcmp(recv_paras[INDEX_CMD].valuestr, recv_cmd_type[ENTER_CMD].name)) || \
		(!strcmp(recv_paras[INDEX_CMD].valuestr, recv_cmd_type[EXIT_CMD].name))) {
		send_paras[INDEX_TEST_ITEM].opt = true;
		send_paras[INDEX_RESULT].opt = true;
	} else if ((!strcmp(recv_paras[INDEX_CMD].valuestr, recv_cmd_type[START_CMD].name)) || \
		(!strcmp(recv_paras[INDEX_CMD].valuestr, recv_cmd_type[STOP_CMD].name))) {
		send_paras[INDEX_RESULT].opt = true;
	}
	if (!strcmp(status, NAK_STA))
		send_paras[INDEX_RESULT].opt = true;

	if ((!send_paras[INDEX_TYPE].opt) && send_paras[INDEX_RES].name)
		strcpy(send_paras[INDEX_TYPE].valuestr, send_paras[INDEX_RES].name);

	if ((!send_paras[INDEX_TEST_ITEM].opt) && recv_paras[INDEX_TEST_ITEM].valuestr)
		strcpy(send_paras[INDEX_TEST_ITEM].valuestr, recv_paras[INDEX_TEST_ITEM].valuestr);

	if ((!send_paras[INDEX_RES].opt) && recv_paras[INDEX_CMD].valuestr)
		strcpy(send_paras[INDEX_RES].valuestr, recv_paras[INDEX_CMD].valuestr);

	if ((!send_paras[INDEX_MSG].opt) && msg)
		strcpy(send_paras[INDEX_MSG].valuestr, msg);

	if ((!send_paras[INDEX_STATUS].opt) && status)
		strcpy(send_paras[INDEX_STATUS].valuestr, status);

	if ((!send_paras[INDEX_RESULT].opt) && result)
		strcpy(send_paras[INDEX_RESULT].valuestr, result);

	if (!send_paras[INDEX_ERRCODE].opt) {
		snprintf(str_err_code, sizeof(str_err_code), "%d\0", err_code);
		strcpy(send_paras[INDEX_ERRCODE].valuestr, str_err_code);
	}
}

static int tcp_command_creat(char *send_buf, int send_size, PCBA_SINGLE_PARA *send_paras)
{
	int ret = 0;
	int num = 0;
	char * out;
	cJSON *sendJSON;

	sendJSON = cJSON_CreateObject();
	if (sendJSON == NULL) {
		log_err("cJSON_CreateObject error (%s)\n", cJSON_GetErrorPtr());
		return SEND_FORMAT_ERR;
	}

	for(num = 0; num < SEND_COMMAND_PARANUM; num++) {
		if(send_paras[num].opt)
			continue;
		cJSON_AddStringToObject(sendJSON, send_paras[num].name, send_paras[num].valuestr);
	}
	out = cJSON_Print(sendJSON);
	if (NULL == out) {
		log_err("send command cJSON_Print error\n");
		cJSON_Delete(sendJSON);
		return SEND_FORMAT_ERR;
	}

	if (strlen(out) > send_size) {
		log_err("send command size is %d exceed %d \n", strlen(out), send_size);
		ret = SEND_FORMAT_ERR;
		goto EXIT;
	}

	strcpy(send_buf, out);

EXIT:
	cJSON_Delete(sendJSON);
	free(out);

	return ret;
}

static int tcp_command_send(int stock_fd, PCBA_COMMAND_PARA *cmd_paras, char *status,
	char *msg, char *result, int err_code)
{
	int ret = 0;
	int send_num = 0;
	char send_buf[SEND_BUFFER_SIZE];

	tcp_command_fill(cmd_paras, status, msg, result, err_code);
	ret = tcp_command_creat(send_buf, sizeof(send_buf), cmd_paras->send_paras);
	if (ret) {
		log_err("send command creat fail, ret=%d\n", ret);
		return ret;
	}

	send_num = send(stock_fd, send_buf, sizeof(send_buf), 0);
	log_info("send_buf is :%s \n",send_buf);
	if (send_num < 0) {
		log_err("command tcp send fail, send_num=%d\n", send_num);
		return TCP_SEND_ERR;
	}

	return 0;
}

static void tcp_command_para_init(PCBA_COMMAND_PARA *cmd_paras)
{
	int num = 0;

	memset(cmd_paras, 0, sizeof(PCBA_COMMAND_PARA));
	for (num = 0; num < RECV_COMMAND_PARANUM; num++) {
		strcpy(cmd_paras->recv_paras[num].name, recv_cmd_target[num].name);
		cmd_paras->recv_paras[num].opt = recv_cmd_target[num].opt;
	}
	for (num = 0; num < SEND_COMMAND_PARANUM; num++)
		strcpy(cmd_paras->send_paras[num].name, send_cmd_target[num].name);
}

static int tcp_command_parse(char *recv_buf, PCBA_SINGLE_PARA *recv_paras)
{
	int num = 0;
	int ret = 0;
	int err_code = 0;
	cJSON *recvJSON;
	cJSON *sub_JSON;

	recvJSON = cJSON_Parse(recv_buf);
	if (recvJSON == NULL) {
		log_err("command JSON parse error (%s)\n", cJSON_GetErrorPtr());
		return RECV_FORMAT_ERR;
	} else {
		for (num = 0; num < RECV_COMMAND_PARANUM; num++) {
			sub_JSON = cJSON_GetObjectItem(recvJSON , recv_paras[num].name);
			if (sub_JSON) {
				if ((sub_JSON->type != cJSON_String) || (sub_JSON->valuestring == NULL)) {
					log_err("parse json type error(%d) or null string \n", sub_JSON->type);
					ret = RECV_FORMAT_ERR;
					goto ERR_EXIT;
				}
				if (strlen(sub_JSON->valuestring) > sizeof(recv_paras[num].valuestr)) {
					log_err("recv string length is %d exceed %d \n",
						strlen(sub_JSON->valuestring), sizeof(recv_paras[num].valuestr));
					ret = CMD_OVERLONG;
					goto ERR_EXIT;
				}
				strcpy(recv_paras[num].valuestr, sub_JSON->valuestring);
				if (!err_code) {
					err_code = tcp_command_check(num, sub_JSON->valuestring);
					if (err_code) {
						ret = err_code;
						log_err("check command %s error\n", recv_paras[num].name);
					}
				}
			} else if (recv_paras[num].opt == false) {
				 log_err("not receive (%s)\n", recv_paras[num].name);
				 ret = RECV_FORMAT_ERR;
				 goto ERR_EXIT;
			}
		}
	}
ERR_EXIT:
	cJSON_Delete(recvJSON);

	return ret;
}

static int tcp_command_process(int stock_fd, int err_code, PCBA_COMMAND_PARA *cmd_paras)
{
	int ret = -1;
	int fork_status = PARENT_EXIT;
	static char test_flag = 0;
	char status[COMMAND_VALUESIZE] = NAK_STA;
	char msg[COMMAND_VALUESIZE] = {0};
	char result[COMMAND_VALUESIZE] = RESULT_TESTING;
	PCBA_SINGLE_PARA *recv_paras = cmd_paras->recv_paras;

    log_info("recv_paras[INDEX_TEST_ITEM].valuestr is :%s---------\n",recv_paras[INDEX_TEST_ITEM].valuestr);
	if (err_code)
		goto SEND_CMD;

	if (!strcmp(recv_paras[INDEX_CMD].valuestr, recv_cmd_type[ENTER_CMD].name)) {
		err_code = enter_pcba_test_mode(recv_paras, &test_flag);
	} else if (!strcmp(recv_paras[INDEX_CMD].valuestr, recv_cmd_type[EXIT_CMD].name)) {
	    usleep(2000);  //休眠2ms让PC端有时间读取结果
		err_code = exit_pcba_test_mode(recv_paras, &test_flag);
	} else if (!strcmp(recv_paras[INDEX_CMD].valuestr, recv_cmd_type[START_CMD].name)) {
		err_code = start_pcba_test_preproccess(recv_paras, test_flag);
		if ((!err_code) && !strcmp(recv_paras[INDEX_TEST_ITEM].valuestr, STORAGE_TESTITEM)) {
			fork_status = start_pcba_test_proccess(recv_paras, &err_code);
			if (fork_status != CHILD_EXIT)
				goto EXIT;
			if (!err_code) {
				ret = query_test_result(recv_paras, msg, result, &err_code);
				if (ret)
					err_code = ret;
			}
		}
	} else if (!strcmp(recv_paras[INDEX_CMD].valuestr, recv_cmd_type[STOP_CMD].name)) {
		err_code = stop_pcba_test(recv_paras);
	} else if (!strcmp(recv_paras[INDEX_CMD].valuestr, recv_cmd_type[QUERY_CMD].name)) {
		if (ret = query_test_result(recv_paras, msg, result, &err_code))
			err_code = ret;
	} else {
		err_code = CMD_ERR;
	}

SEND_CMD:
    if (err_code & ret)
		strcpy(status, NAK_STA);
	else
		strcpy(status, ACK_STA);

	ret = tcp_command_send(stock_fd, cmd_paras, status, msg, result, err_code);
	if (ret) {
		log_err("command send fail, err=%d\n", ret);
		goto EXIT;
	}
	if (err_code) {
		log_err("command process fail, err_code=%d\n", err_code);
		goto EXIT;
	}

    if (!strcmp(recv_paras[INDEX_CMD].valuestr, recv_cmd_type[START_CMD].name)){
        if(!strcmp(recv_paras[INDEX_TEST_ITEM].valuestr, STORAGE_TESTITEM)){
            goto EXIT;
        }
        fork_status = start_pcba_test_proccess(recv_paras, &err_code);
    }

EXIT:

	return fork_status;
}

static void tcp_client_process(int stock_fd)
{
    PCBA_COMMAND_PARA cmd_paras_set;
	PCBA_COMMAND_PARA *cmd_paras = &cmd_paras_set;
	int recv_num = 0;
	int parse_ret = 0;
	int proc_ret = 0;
	char recv_buf[RECV_BUFFER_SIZE] = {0};

	//cmd_paras = (PCBA_COMMAND_PARA *)malloc(sizeof(PCBA_COMMAND_PARA));
//	if (!cmd_paras) {
//		log_err("malloc cmd_paras faild\n");
//		goto ERR_EXIT;
//	}

	while(1) {
		log_info("waiting for client...\n");
		recv_num = recv(stock_fd, recv_buf, sizeof(recv_buf), 0);
		log_info("recv_buf is :%s \n",recv_buf);
		if (recv_num <= 0) {
			log_err("recv error:%s\n", strerror(errno));
			goto ERR_FREE_EXIT;
		}
		recv_buf[recv_num]='\0';

		tcp_command_para_init(cmd_paras);

		parse_ret = tcp_command_parse(recv_buf, cmd_paras->recv_paras);
		if (parse_ret == RECV_FORMAT_ERR)
			continue;

		proc_ret = tcp_command_process(stock_fd, parse_ret, cmd_paras);
		if (proc_ret == FORK_FAIL){
            goto ERR_FREE_EXIT;
        }

		else if (proc_ret == CHILD_EXIT)
			goto EXIT;
	}

ERR_FREE_EXIT:
	//free(cmd_paras);
ERR_EXIT:
	close(stock_fd);
	exit(-1);
EXIT:
	//free(cmd_paras);
	exit(0);
}

static int init_tcp(void)
{
	int val = 1;
	int server_sockfd;
	struct sockaddr_in server_addr;
	int ret;

	/* create a socket */
	server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_sockfd < 0) {
		log_err("socket error:%s\n", strerror(errno));
		return -1;
	}

	ret = setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&val, sizeof(int));
	if (ret == -1) {
		log_err("setsockopt error:%s\n", strerror(errno));
		return -1;
	}

	/*  initialize server address */
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(SOURCE_PORT);

	/* bind with the local file */
	ret = bind(server_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	if (ret) {
		log_err("bind error:%s\n", strerror(errno));
		close(server_sockfd);
		return -1;
	}

	/* listen */
	ret = listen(server_sockfd, TCP_QUEUE_LINE);
	if (ret) {
		log_err("listen error:%s\n", strerror(errno));
		close(server_sockfd);
		return -1;
	}
	log_info("tcp server is ready ... \n");

	return server_sockfd;
}

int main(int argc, char **argv)
{
	int server_sockfd;
	int client_sockfd;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	pid_t pid;

	signal(SIGCHLD, sig_child_handle);

	server_sockfd = init_tcp();
	if (server_sockfd < 0)
		log_err("tcp server init fail\n");

	while(1) {
		/* accept a connection */
		client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_addr, &client_addr_len);
		if (client_sockfd < 0) {
			log_err("accept error:%s\n", strerror(errno));
			close(server_sockfd);
			return -1;
		}

		log_info("accept a new client, ip:%s, port:%d\n",
			 inet_ntoa(client_addr.sin_addr),
			 ntohs(client_addr.sin_port));

		pid = fork();
		if (pid < 0) {
			log_err("fork tcp_client_process error\n");
			close(server_sockfd);
			return -1;
		} else if (0 == pid) {
			close(server_sockfd);
			tcp_client_process(client_sockfd);

			//_exit(0);  //new added to exit child process
		} else if (pid > 0) {
			close(client_sockfd);
		}
	}
	close(server_sockfd);

	return 0;
}
