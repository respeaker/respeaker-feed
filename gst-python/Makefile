#
# Copyright (C) 2008-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gst-python
# PKG_VERSION:=0.10.13
PKG_VERSION:=1.2.1
PKG_RELEASE:=1
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://gstreamer.freedesktop.org/src/gst-python/
# PKG_MD5SUM:=870440c6aad304112961ef5700d7698f
PKG_MD5SUM:=f80b3503b46aad0a5f8ec0903910cd57
# PKG_FIXUP:=autoreconf
# PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk
$(call include_mk, python-package.mk)

# TARGET_CFLAGS += $(FPIC)
# CONFIGURE_VARS += PYTHON=$(HOST_PYTHON)

define Package/python-gst
  SECTION:=respeaker
  CATEGORY:=ReSpeaker
  TITLE:=python bindings for gstreamer
  URL:=http://gstreamer.freedesktop.org/
  DEPENDS:=+libgstreamer1 +python +python-gi +libgirepository
endef

define Package/python-gst/description
  python bindings for gstreamer
endef

define Package/python-gst/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)/gi/overrides
	$(CP) $(PKG_BUILD_DIR)/gi/overrides/G*.py $(1)$(PYTHON_PKG_DIR)/gi/overrides
	$(CP) $(PKG_BUILD_DIR)/gi/overrides/.libs/_gi_gst.so $(1)$(PYTHON_PKG_DIR)/gi/overrides
endef

$(eval $(call BuildPackage,python-gst))
