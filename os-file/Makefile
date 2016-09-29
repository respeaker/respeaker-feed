#
# Copyright (C) 2016 Baozhu Zuo <baozhu.zuo@gmail.com>
#
# This is free software, licensed under the GPL 2 license.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=respeaker-os-file
PKG_VERSION:=2016-09-07
PKG_RELEASE=$(PKG_SOURCE_VERSION)


include $(INCLUDE_DIR)/package.mk

define Package/respeaker-os-file
  SECTION:=respeaker
  CATEGORY:=ReSpeaker
  TITLE:=ReSpeaker os file
  DEPENDS:=+avrdude +gmrender-resurrect +alsa-utils +alsa-lib
  ABI_VERSION:=$(PKG_RELEASE)
endef

define Package/respeaker-os-file/description
	ReSpeaker os files
endef

define Build/Configure
endef


define Build/Compile
endef

define Package/respeaker-os-file/install
	 $(CP) ./files/* $(1)
endef

$(eval $(call BuildPackage,respeaker-os-file))
