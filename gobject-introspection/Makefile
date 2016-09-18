#
# Copyright (C) 2016 Seeed Technology Limited.
#
# This is free software, licensed under the GPL 2 license.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gobject-introspection
PKG_VERSION:=2016-09-14
PKG_RELEASE=$(PKG_SOURCE_VERSION)


include $(INCLUDE_DIR)/package.mk

define Package/gobject-introspection
  SECTION:=respeaker
  CATEGORY:=ReSpeaker
  TITLE:=gobject-introspection
  ABI_VERSION:=$(PKG_RELEASE)
endef

define Package/gobject-introspection/description
	gobject-introspection
endef

define Build/Configure
endef


define Build/Compile
endef

define Build/InstallDev
	$(CP) ./files/* $(1)
endef

define Package/gobject-introspection/install
endef

$(eval $(call BuildPackage,gobject-introspection))
