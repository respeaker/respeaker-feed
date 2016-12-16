#
# Copyright (c) 2016 Seeed Technology Limited.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=webrtc-audio-processing
PKG_VERSION:=master
PKG_RELEASE=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://git.oschina.net/yihui/webrtc-audio-processing.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_FIXUP:=./autogen.sh
PKG_INSTALL=1


include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk

define Package/webrtc-audio-processing
  SECTION:=respeaker
  CATEGORY:=ReSpeaker
  DEPENDS:=+libstdcpp +libpthread +librt
  TITLE:=WebRTC Audio Processing Library
endef

define Package/webrtc-audio-processing/description
	webrtc audio processing
endef

CONFIGURE_CMD =./autogen.sh

define Build/InstallDev
	$(CP) $(PKG_INSTALL_DIR)/* $(1)/
endef

define Package/webrtc-audio-processing/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libwebrtc_audio_processing.so.* $(1)/usr/lib
endef

$(eval $(call BuildPackage,webrtc-audio-processing))
