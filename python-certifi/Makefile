#
# Copyright (c) 2015 Quatanium Co., Ltd.
#
# Licensed under MIT.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=certifi
PKG_VERSION:=2016.8.8
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://pypi.python.org/packages/41/bf/88a3269c7c95fc94a2c581c4b1b3d3ec21af7a268d6a3a4e54578adccfd6/
PKG_MD5SUM:=b57513f7670482da45bb350b792f659e
PKG_BUILD_DEPENDS:=python

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-certifi
	SECTION:=Python
	CATEGORY:=ReSpeaker
	TITLE:=python-certifi
	URL:=https://pypi.python.org/pypi/six
	DEPENDS:=+python
endef

define Package/python-certifi/description
	Python package for providing Mozilla's CA Bundle.
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix=/usr --root=$(PKG_INSTALL_DIR))
endef

define Package/python-certifi/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)/
	$(CP) \
		$(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
		$(1)$(PYTHON_PKG_DIR)/
endef

$(eval $(call BuildPackage,python-certifi))
