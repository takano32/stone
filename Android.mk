LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := stone
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES := libc libcutils libcrypto libssl
LOCAL_CFLAGS := -DANDROID -DCONST_SSL_METHOD -DTHREAD_UNSAFE -DNO_RINDEX -DPTHREAD -DUNIX_DAEMON -DUSE_POP -DUSE_SSL
LOCAL_SRC_FILES := stone.c
LOCAL_C_INCLUDES := external/openssl/include frameworks/base/cmds/keystore

include $(BUILD_EXECUTABLE)
