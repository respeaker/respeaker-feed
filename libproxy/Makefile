#
# Copyright (c) 2016 Seeed Technology Limited.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libproxy
PKG_VERSION:=0.4.13
PKG_RELEASE=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/libproxy/libproxy.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

# PKG_FIXUP:=cmake

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/libproxy
  SECTION:=respeaker
  CATEGORY:=ReSpeaker
  DEPENDS:=+libstdcpp +libpthread
  TITLE:=libproxy
endef

define Package/libproxy/description
  libproxy
endef

# CONFIGURE_ARGS+= 

# define Build/Configure
	# $(CMAKE) $(PKG_BUILD_DIR)/CMakeLists.txt
# endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_BUILD_DIR)/libproxy-1.0.pc $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_BUILD_DIR)/libproxy/libproxy.so* $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/libproxy/proxy.h $(1)/usr/include
endef

define Package/libproxy/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libproxy/libproxy.so.1* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libproxy))
