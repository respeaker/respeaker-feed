#
# Copyright (C) 2013 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gmediarender
PKG_VERSION:=2013-12-04
PKG_RELEASE=$(PKG_SOURCE_VERSION)

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com:hzeller/gmrender-resurrect.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=e2eb7852eebea95c69c79c43a1e4d5f52409930f
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_FIXUP:=autoreconf
PKG_INSTALL=1
PKG_REMOVE_FILES:=autogen.sh aclocal.m4

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/gmediarender
  SECTION:=multimedia
  CATEGORY:=Multimedia
  DEPENDS:= +gstreamer1 +glib2 +libupnp
  TITLE:=A Headless UPnP Renderer
endef

define Package/gmediarender/description
  gmediarender implements the server component that provides UPnP
  controllers a means to render media content (audio, video and images)
  from a UPnP media server.
endef

CONFIGURE_ARGS+= \
	--with-build-cc="$(HOSTCC)" \
	--prefix="\usr"

define Package/gmediarender/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/$(PKG_NAME) $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/gmediarender.init $(1)/etc/init.d/gmediarender
endef

$(eval $(call BuildPackage,gmediarender))
