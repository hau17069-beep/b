export ARCHS = arm64 arm64e
export TARGET = iphone:clang:latest:14.0
export THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = LCProtectionRecon
LCProtectionRecon_FILES = Tweak.xm
LCProtectionRecon_CFLAGS = -fobjc-arc
LCProtectionRecon_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk