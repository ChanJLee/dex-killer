LOCAL_PATH := $(call my-dir)

TARGET_PIE := true
NDK_APP_PIE := true
APP_STL := stlport_static

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  sha1.cpp \
  dex_killer.cpp \
  main.cpp

LOCAL_C_INCLUDE := \
  definitions.h  \
  dex_killer.h \
  sha1.h

LOCAL_MODULE := dex_killer
LOCAL_MODULE_TAGS := optional

# Allow execution on android-16+
LOCAL_CFLAGS += -fPIE
LOCAL_LDFLAGS += -fPIE -pie

LOCAL_LDLIBS := -L$(SYSROOT)/usr/lib -llog

include $(BUILD_EXECUTABLE)

include $(call all-makefiles-under,$(LOCAL_PATH))
