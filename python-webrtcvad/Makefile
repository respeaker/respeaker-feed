#
# Copyright (C) 2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-webrtcvad
PKG_VERSION:=2.0.7
PKG_RELEASE:=1
PKG_MAINTAINER:=Yihui Xiong <yihui_xiong@163.com>
PKG_LICENSE:=Python-2.0

PKG_SOURCE:=webrtcvad-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://pypi.python.org/packages/14/c7/11170cd80c95b4a9e0404004c8c7515c384d8d4f9a483c67304c1f3fe11c/
PKG_MD5SUM:=54a301b0f15a502f26cffa70882696ac
PKG_BUILD_DIR:=$(BUILD_DIR)/webrtcvad-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python python-setuptools

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-webrtcvad
  SECTION:=Python
  CATEGORY:=ReSpeaker
  TITLE:=Python interface to the WebRTC Voice Activity Detector
  URL:=https://github.com/wiseman/py-webrtcvad
  DEPENDS:=+python-light
endef

define Package/python-webrtcvad/description
  This is a python interface to the WebRTC Voice Activity Detector (VAD). 
  It is compatible with Python 2 and Python 3. A VAD classifies a piece of
  audio data as being voiced or unvoiced. It can be useful for telephony
  and speech recognition. The VAD that Google developed for the WebRTC
  project is reportedly one of the best available, being fast, modern and free.
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix="$(PKG_INSTALL_DIR)/usr")
endef

define Package/python-webrtcvad/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) \
	    $(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
	    $(1)$(PYTHON_PKG_DIR)
endef

$(eval $(call BuildPackage,python-webrtcvad))
