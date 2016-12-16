#
# Copyright (C) 2016 Seeed Technology Limited.
#
# This is free software, licensed under the GPL 2 license.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=alexa
PKG_VERSION:=2016-12-16
PKG_RELEASE=$(PKG_SOURCE_VERSION)


include $(INCLUDE_DIR)/package.mk

define Package/alexa
  SECTION:=respeaker
  CATEGORY:=ReSpeaker
  TITLE:=Alexa
  DEPENDS:=
  ABI_VERSION:=$(PKG_RELEASE)
endef

define Package/alexa/description
	Alexa Voice Service
endef

define Build/Configure
endef


define Build/Compile
endef

define Package/alexa/install
	 $(INSTALL_DIR) $(1)/usr/bin
	 $(INSTALL_BIN) ./files/alexa.py $(1)/usr/bin/alexa
	 $(INSTALL_DIR) $(1)/root
	 $(CP) ./files/alexa_hint.mp3 $(1)/root
	 $(INSTALL_DIR) $(1)/etc/init.d
	 $(INSTALL_BIN) ./files/alexa.init $(1)/etc/init.d/alexa
endef

$(eval $(call BuildPackage,alexa))
