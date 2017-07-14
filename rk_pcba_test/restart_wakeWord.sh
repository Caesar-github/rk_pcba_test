export CLASSPATH=/data/libs/sample-java-client-20160207.3.jar:/data/libs/commons-codec-1.9.jar:/data/libs/commons-io-2.4.jar:/data/libs/commons-lang3-3.4.jar:/data/libs/commons-fileupload-1.3.1.jar:/data/libs/vlcj-2.4.1.jar:/data/libs/jna-4.1.0.jar:/data/libs/platform-3.5.2.jar:/data/libs/javax.json-1.0.4.jar:/data/libs/jlayer-1.0.1.jar:/data/libs/alpn-boot-8.1.11.v20170118.jar:/data/libs/jackson-mapper-asl-1.9.13.jar:/data/libs/jackson-core-asl-1.9.13.jar:/data/libs/slf4j-api-1.7.10.jar:/data/libs/log4j-slf4j-impl-2.3.jar:/data/libs/log4j-api-2.3.jar:/data/libs/log4j-core-2.3.jar:/data/libs/jetty-alpn-client-9.3.7.v20160115.jar:/data/libs/jetty-http-9.3.7.v20160115.jar:/data/libs/http2-client-9.3.7.v20160115.jar:/data/libs/http2-http-client-transport-9.3.7.v20160115.jar:/data/libs/http2-hpack-9.3.7.v20160115.jar:/data/libs/http2-common-9.3.7.v20160115.jar:/data/libs/jetty-server-9.3.7.v20160115.jar:/data/libs/jetty-security-9.3.7.v20160115.jar:/data/libs/jetty-servlet-9.3.7.v20160115.jar:/data/libs/jetty-util-9.3.7.v20160115.jar:/data/libs/jetty-io-9.3.7.v20160115.jar:/data/libs/jetty-client-9.3.7.v20160115.jar:/data/libs/javax.servlet-api-3.1.0.jar:$CLASSPATH
export JAVA_HOME=/data/jre1.8.0_121
export PATH=$JAVA_HOME/bin:$PATH
export CLASSPATH=$CLASSPATH:$JAVA_HOME/lib:$JAVA_HOME/lib/tools.jar
date -s "2017-04-11 20:58:00"

if busybox ps | grep wakeWordAgent | grep -v grep; then
	echo "wakeWordAgent already exist ..."
else
	reboot
	busybox killall wpa_supplicant
	busybox killall gmediarender
	busybox killall bluetoothd
	busybox killall brcm_patchram_plus1
	echo 1 > /sys/class/rfkill/rfkill0/state

	wpa_supplicant -i wlan0 -c /data/cfg/wpa_supplicant.conf &
	cd /data
	./wakeWordAgent -e gpio &
fi

# export KITT_AI_OPEN=true

# #update cx20921
# #/data/cx20921/i2c_flash -d /dev/i2c-0 -g 28 -f /data/cx20921/evk-nebula-generic-6.97.0.0.sfs /data/cx20921/iflash.bin