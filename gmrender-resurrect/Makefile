#
# Copyright (c) 2016 Seeed Technology Limited.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gmrender-resurrect
PKG_VERSION:=2016-05-28
PKG_RELEASE=$(PKG_SOURCE_VERSION)

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/hzeller/gmrender-resurrect.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=48caaa4f6c386fd1586126c801cd326f96d5fa5c
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_FIXUP:=autoreconf
PKG_INSTALL=1
PKG_REMOVE_FILES:=autogen.sh aclocal.m4

PKG_BUILD_DEPENDS:=gstreamer1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/gmrender-resurrect
  SECTION:=respeaker
  CATEGORY:=ReSpeaker
  DEPENDS:= +gstreamer1 +glib2 +libupnp
  TITLE:=A Headless UPnP Renderer
endef

define Package/gmrender-resurrect/description
  Resource efficient UPnP/DLNA renderer, optimal for Raspberry Pi, CuBox or a general MediaServer. Fork of GMediaRenderer to add some features to make it usable.
endef

CONFIGURE_ARGS+= \
	--with-build-cc="$(HOSTCC)" \
	--prefix="\usr"

define Package/gmrender-resurrect/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/gmediarender $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/gmediarender.init $(1)/etc/init.d/gmediarender
endef

$(eval $(call BuildPackage,gmrender-resurrect))
