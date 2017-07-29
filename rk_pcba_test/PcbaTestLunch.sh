#!/bin/busybox sh

#cd /sys/class/android_usb/android0
echo 0 > /sys/class/android_usb/android0/enable
echo rk3036 > /sys/class/android_usb/android0/iProduct
echo rndis,adb > /sys/class/android_usb/android0/functions
echo 2207 > /sys/class/android_usb/android0/idVendor
echo 0013 > /sys/class/android_usb/android0/idProduct
echo 1 > /sys/class/android_usb/android0/enable


#启动PCBA测试服务器程序
if busybox ps | grep echo_pcbatest_server | grep -v grep; then
	echo "echo_pcbatest_server already exist, restart ..."
	busybox killall echo_pcbatest_server
	echo_pcbatest_server &
else
	echo_pcbatest_server &
fi

#启动PCBA测试中的被搜索服务
if busybox ps | grep echo_uevent_detect | grep -v grep; then
	echo "uevent_detect already exist, restart ..."
	busybox killall echo_uevent_detect
	echo_uevent_detect &
else
	echo_uevent_detect &
fi
