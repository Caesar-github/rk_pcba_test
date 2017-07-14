/*
 *  echo_uevent_detect.c  --  usb uevent detect application
 *
 *  Copyright (c) 2017 Rockchip Electronics Co. Ltd.
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
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h>

#define UEVENT_MSG_LEN 1024
#define true 1
#define USB_EVENT_PATH "/sys/class/android_usb/android0/state"

struct uevent{
    const char *action;
    const char *path;
    const char *subsystem;
    const char *firmware;
    int major;
    int minor;
}uevent;
static int uevent_open_socket(int buf_sz);
static void parse_event(const char *msg, struct uevent *uevent);
static int usb_state_get(void);

//* 获取USB线的拔插状态，和PC连接上返回1，否则返回0
static int usb_state_get(void)
{
    char cmd[64];
    char buf[32];
    FILE* pp;

     //首先确定获取USB 拔插状态的路径
    sprintf(cmd,"cat %s",USB_EVENT_PATH);
    pp = popen(cmd,"r");
    //如果文件打开失败，则输出错误信息
    if (!pp)
    {
        printf("%s popen err%s\n",__func__,strerror(errno));
        return -1;
    }

    // *获取USB线的拔插状态，插上时为”CONFIGURED"，拔下时为"DISCONNECTED"
    fgets(buf,sizeof(buf),pp);
    fclose(pp);
    printf("usb state is: %s\n",buf);
    if(!memcmp(buf,"CONFIGURED",strlen("CONFIGURED")))
        return 1;
    else
        return 0;
}



int main(int argc, char* argv[])
{
    int device_fd = -1;
    char msg[UEVENT_MSG_LEN+2];
    int n;

    //创建NETLINK socket，用于监听内核发送过来的uevent消息
    device_fd = uevent_open_socket(64*1024);
    if(device_fd < 0)
        return;
    printf("device_fd = %d\n", device_fd);

    do {
        while((n = recv(device_fd, msg, UEVENT_MSG_LEN, 0)) > 0) {
            //如果读取的内容长度大于1024，继续读取
            if(n >= UEVENT_MSG_LEN)   /* overflow -- discard */
                continue;

            msg[n] = '\0';
            msg[n+1] = '\0';

            //将uevent消息解析成uevent类型的事件
            struct uevent uevent;
            parse_event(msg, &uevent);

            //处理uevent事件，运行处理程序,假如USB线连着PC，则运行自动IP分配脚本
            if(strstr(uevent.subsystem,"usb")){
                if(1==usb_state_get()){
                    system("ipconfig.sh");
                }
                else
                {
                    printf("USB not Connected\n");
                    system(" kill `ps | grep echo.*test|grep -v echo_pcbatest_server|\
                           grep -v grep|awk '{print $1}'`");
                }
                    //printf("USB not Connected\n");
            }
            else
            {
                //printf("Not USB event \n");
            }
        }
    }
    while(1);
}

//创建NETLINK socket,用于监听内核发送过来的uevent消息
static int uevent_open_socket(int buf_sz)
{
    struct sockaddr_nl addr;
    int on = 1;
    int s;

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 0xffffffff;
    //创建socket
    s = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    if(s < 0)
        return -1;
    //设置该socket属性
    setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &buf_sz, sizeof(buf_sz));
    setsockopt(s, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));
    //绑定该socket
    if(bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(s);
        return -1;
    }
    return s;
}

//* 事件解析
static void parse_event(const char *msg, struct uevent *uevent)
{
    uevent->action = "";
    uevent->path = "";
    uevent->subsystem = "";
    uevent->firmware = "";
    uevent->major = -1;
    uevent->minor = -1;

        /* currently ignoring SEQNUM */
    while(*msg) {
        if(!strncmp(msg, "ACTION=", 7)) {
            msg += 7;
            uevent->action = msg;
        } else if(!strncmp(msg, "DEVPATH=", 8)) {
            msg += 8;
            uevent->path = msg;
        } else if(!strncmp(msg, "SUBSYSTEM=", 10)) {
            msg += 10;
            uevent->subsystem = msg;
        } else if(!strncmp(msg, "FIRMWARE=", 9)) {
            msg += 9;
            uevent->firmware = msg;
        } else if(!strncmp(msg, "MAJOR=", 6)) {
            msg += 6;
            uevent->major = atoi(msg);
        } else if(!strncmp(msg, "MINOR=", 6)) {
            msg += 6;
            uevent->minor = atoi(msg);
        }

        /* advance to after the next \0 */
        while(*msg++)
            ;
    }
    if(strstr(uevent->subsystem,"usb")){
        printf("event { '%s', '%s', '%s', '%s', %d, %d }\n",
        uevent->action, uevent->path, uevent->subsystem,
        uevent->firmware, uevent->major, uevent->minor);
    }
}
