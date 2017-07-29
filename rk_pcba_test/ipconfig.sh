#!/bin/busybox sh
#分配固定IP地址



ifconfig rndis0 169.254.2.10 netmask 255.255.0.0 up
route add default gw 169.254.2.1 rndis0

#查看网络ip配置情况
ifconfig rndis0
route -n

# 启动IP地址分配
if busybox ps | grep dnsmasq | grep -v grep; then
		echo "dnsmasq already exist, restart ..."
#        busybox killall dnsmasq
#        dnsmasq -0 6 -C /data/bin/dnsmasq.conf &
else
		echo "dnsmasq start ..."
        dnsmasq -0 6 -C /data/bin/dnsmasq_rndis.conf &
fi

#如果2s内还未分配好IP地址，则windows端使用默认的
busybox sleep 2
busybox kill `pidof -s dnsmasq`

#启动PCBA测试中的被搜索服务
if busybox ps | grep echo_discovery | grep -v grep; then
	echo "echo_discovery already exist, restart ..."
#	busybox killall echo_discovery
#	echo_discovery &
else
	echo "echo_discovery start ..."
	echo_discovery &
fi

