#
# Copyright (C) 2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-pyaudio
PKG_VERSION:=0.2.9
PKG_RELEASE:=1
PKG_MAINTAINER:=Yihui Xiong <yihui_xiong@163.com>
PKG_LICENSE:=Python-2.0

PKG_SOURCE:=PyAudio-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://pypi.python.org/packages/d0/dc/ffb9ce5e3f19bd289902915a9f68b7d199216065f8ea17d5b5e8e4ad86ee/
PKG_MD5SUM:=6d91aae842c7000d2921815e286801fd
PKG_BUILD_DIR:=$(BUILD_DIR)/PyAudio-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python python-setuptools portaudio

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-pyaudio
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=python-pyaudio
  URL:=https://people.csail.mit.edu/hubert/pyaudio
  DEPENDS:=+python-light +portaudio
endef

define Package/python-pyaudio/description
	portaudio audio sound python bindings
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix="$(PKG_INSTALL_DIR)/usr")
endef

define Package/python-pyaudio/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) $(PKG_BUILD_DIR)/build/lib.linux2-2.7/* \
	    $(1)$(PYTHON_PKG_DIR)
endef

$(eval $(call BuildPackage,python-pyaudio))
