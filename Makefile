TARGET := iphone:clang:latest:15.0
ARCHS := arm64
INSTALL_TARGET_PROCESSES = Nulls Brawl

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = TaleMod
TaleMod_FILES = src/Tweak.mm
TaleMod_CFLAGS = -fobjc-arc -Iinclude -Wno-unused-function -Wno-unused-variable -Wl,-undefined,dynamic_lookup
TaleMod_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
