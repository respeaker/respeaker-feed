#
# Copyright (C) 2016 Baozhu Zuo <baozhu.zuo@gmail.com>
#
# This is free software, licensed under the GPL 2 license.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libgirepository
PKG_VERSION:=2016-09-14
PKG_RELEASE=$(PKG_SOURCE_VERSION)


include $(INCLUDE_DIR)/package.mk

define Package/libgirepository
  SECTION:=respeaker
  CATEGORY:=ReSpeaker
  TITLE:=libgirepository
  DEPENDS:=+glib2 +libffi +gobject-introspection
  ABI_VERSION:=$(PKG_RELEASE)
endef

define Package/libgirepository/description
	libgirepository
endef

define Build/Configure
endef


define Build/Compile
endef

define Build/InstallDev
	$(CP) ./files/* $(1)
endef

define Package/libgirepository/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) ./files/usr/lib/*.so* $(1)/usr/lib
endef

$(eval $(call BuildPackage,libgirepository))
