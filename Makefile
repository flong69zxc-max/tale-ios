TARGET := iphone:clang:latest:15.0
ARCHS := arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Null
Null_FILES = src/Tweak.mm
Null_CFLAGS = -fobjc-arc -Iinclude -Wno-unused-function -Wno-unused-variable -Wl,-undefined,dynamic_lookup
Null_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk