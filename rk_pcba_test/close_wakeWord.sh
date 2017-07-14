#!/bin/busybox sh

#关闭javacmd和wakeWordAgent程序
if busybox ps | grep java | grep -v grep; then
	echo "close java ..."
	busybox killall java 
fi

if busybox ps | grep wakeWordAgent | grep -v grep; then
	echo "close wakeWordAgent ..."
	busybox killall wakeWordAgent 
fi

if busybox ps | grep udhcpc | grep -v grep; then
	echo "close udhcpc ..."
	busybox killall udhcpc 
fi

if busybox ps | grep wpa_supplicant | grep -v grep; then
	echo "close wpa_supplicant ..."
	busybox killall wpa_supplicant 
fi

if busybox ps | grep bluetoothd | grep -v grep; then
	echo "close bluetoothd ..."
	busybox killall bluetoothd 
fi

if busybox ps | grep brcm_patchram_plus1 | grep -v grep; then
	echo "close brcm_patchram_plus1 ..."
	busybox killall brcm_patchram_plus1 
fi