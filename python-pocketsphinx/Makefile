#
# Copyright (C) 2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-pocketsphinx
PKG_VERSION:=0.0.1
PKG_RELEASE:=1
PKG_MAINTAINER:=Yihui Xiong <yihui_xiong@163.com>
PKG_LICENSE:=Python-2.0

PKG_BUILD_DIR:=$(BUILD_DIR)/python-pocketsphinx-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python python-setuptools sphinxbase pocketsphinx

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-pocketsphinx
  SECTION:=Python
  CATEGORY:=ReSpeaker
  TITLE:=python-pocketsphinx
  URL:=https://github.com/xiongyihui/pocketsphinx-python-light
  DEPENDS:=+python-light +alsa-lib +sphinxbase +pocketsphinx
endef

define Package/python-pocketsphinx/description
	alsa audio sound python bindings
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -R ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix="$(PKG_INSTALL_DIR)/usr")
endef

define Package/python-pocketsphinx/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) -R $(PKG_BUILD_DIR)/build/lib.linux2-2.7/* \
	    $(1)$(PYTHON_PKG_DIR)
	$(CP) $(PKG_BUILD_DIR)/pocketsphinx/swig/python/pocketsphinx.py $(1)$(PYTHON_PKG_DIR)/pocketsphinx
	$(CP) $(PKG_BUILD_DIR)/sphinxbase/swig/python/sphinxbase.py $(1)$(PYTHON_PKG_DIR)/sphinxbase
endef

$(eval $(call BuildPackage,python-pocketsphinx))
