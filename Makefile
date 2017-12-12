LOCAL_ARM_MODE := armeabi
all: check build

check:
ifeq (, $(shell which ndk-build))
        $(error "No 'ndk-build' in PATH, please install Android NDK and configure properly")
endif

build:
	ndk-build APP_ABI="armeabi" NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk NDK_APPLICATION_MK=./Application.mk

install:
	adb push libs/armeabi/dex_killer /data/local/tmp/

clean:
	rm -rf *.c~
	rm -rf *.h~
	rm -rf obj/
