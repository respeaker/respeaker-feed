#
# Copyright (C) 2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
# updated to work with latest source from abrasive
#

include $(TOPDIR)/rules.mk

PKG_NAME:=shairport-sync2
PKG_VERSION:=2.8.5
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com/mikebrady/shairport-sync.git
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_MAINTAINER:=Mike Brady <mikebrady@eircom.net>

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSES

PKG_BUILD_PARALLEL:=1

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

CONFIGURE_ARGS+= \
	--with-alsa \
	--with-avahi \
	--with-soxr \
	--with-ssl=openssl \
	--sysconfdir=/etc


define Package/shairport-sync2
  SECTION:=respeaker
  CATEGORY:=ReSpeaker
  TITLE:=iPhone/iTunes compatible audio player
  DEPENDS:= +libpthread +libopenssl +libavahi-client +alsa-lib +libdaemon +libsoxr +libpopt +libconfig
  MAINTAINER:=Mike Brady <mikebrady@eircom.net>
endef

define Package/shairport-sync2/description
  Shairport Sync is server software that implements the Apple-originated RAOP protocol for
  playback of audio from a compatible remote client such as the iPhone, iTunes, Apple TV, Quicktime Player or forked-daapd.
  Shairport Sync implements audio synchronisation, supporting multi-room use.
  Shairport Sync supports audio only.
endef

define Package/shairport-sync2/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/shairport-sync $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/shairport-sync.init $(1)/etc/init.d/shairport-sync
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/shairport-sync.config $(1)/etc/config/shairport-sync
endef

$(eval $(call BuildPackage,shairport-sync2))
