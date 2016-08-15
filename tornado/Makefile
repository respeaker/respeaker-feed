#
# Copyright (C) 2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=tornado
PKG_VERSION:=4.4.1
PKG_MAINTAINER:=Yihui Xiong <yihui_xiong@163.com>
PKG_LICENSE:=Python-2.0

PKG_SOURCE:=tornado-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://pypi.python.org/packages/96/5d/ff472313e8f337d5acda5d56e6ea79a43583cc8771b34c85a1f458e197c3/
PKG_MD5SUM:=fff8a7d7f580b04bacc2ffe7ddf41133
PKG_BUILD_DIR:=$(BUILD_DIR)/tornado-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python python-setuptools python-six python-certifi python-singledispatch python-backports-abc

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-tornado
  SECTION:=Python
  CATEGORY:=ReSpeaker
  TITLE:=Tornado Web Framework
  URL:=https://pypi.python.org/pypi/tornado
  DEPENDS:=+python-light +python-six +python-certifi +python-singledispatch +python-backports-abc
endef

define Package/python-tornado/description
  Tornado
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix="$(PKG_INSTALL_DIR)/usr")
endef

define Package/python-tornado/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)/tornado
	$(CP) \
	    $(PKG_BUILD_DIR)/build/lib.linux2-2.7/tornado/*.py \
	    $(1)$(PYTHON_PKG_DIR)/tornado
	$(CP) \
	    $(PKG_BUILD_DIR)/build/lib.linux2-2.7/tornado/speedups.so \
	    $(1)$(PYTHON_PKG_DIR)/tornado
	$(CP) -R \
	    $(PKG_BUILD_DIR)/build/lib.linux2-2.7/tornado/platform \
	    $(1)$(PYTHON_PKG_DIR)/tornado
	$(CP) $(PKG_BUILD_DIR)/ipkg-install/usr/lib/python2.7/site-packages/site.py $(1)$(PYTHON_PKG_DIR)
endef

$(eval $(call BuildPackage,python-tornado))
