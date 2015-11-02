# export ANDROID_JAVA_HOME=/usr/lib/jvm/java-7-openjdk-amd64
# export TOP=/usr/local/src/android-6.0.0_r1
# . $TOP/build/envsetup.sh 
# mm showcommands

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := stone
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libc libcutils libcrypto libssl libkeystore_binder
LOCAL_CFLAGS := -DANDROID -DNO_SYSLOG -DCONST_SSL_METHOD -DTHREAD_UNSAFE -DNO_RINDEX -DPTHREAD -DUNIX_DAEMON -DSO_ORIGINAL_DST=80 -DUSE_POP -DUSE_SSL
LOCAL_SRC_FILES := stone.c
LOCAL_C_INCLUDES := external/openssl/include frameworks/base/cmds/keystore system/security/keystore/include/keystore

include $(BUILD_EXECUTABLE)
