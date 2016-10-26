#
# Copyright (C) 2016 Seeed Technology Limited.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ptyprocess
PKG_VERSION:=0.5.1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://pypi.python.org/packages/db/d7/b465161910f3d1cef593c5e002bff67e0384898f597f1a7fdc8db4c02bf6/
PKG_MD5SUM:=94e537122914cc9ec9c1eadcd36e73a1
PKG_BUILD_DEPENDS:=python

PKG_BUILD_DEPENDS:=+python

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/ptyprocess
	SECTION:=respeaker
	CATEGORY:=ReSpeaker
	TITLE:=ptyprocess
	URL:=https://github.com/pexpect/ptyprocess
	DEPENDS:=+python
endef

define Package/ptyprocess/description
	Run a subprocess in a pseudo terminal
endef

define Build/Compile
	$(call Build/Compile/PyMod,, \
		install --prefix=/usr --root=$(PKG_INSTALL_DIR), \
	)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)/
	$(CP) \
		$(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
		$(1)$(PYTHON_PKG_DIR)/
endef

define Package/ptyprocess/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)/
	$(CP) \
		$(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
		$(1)$(PYTHON_PKG_DIR)/
endef

$(eval $(call BuildPackage,ptyprocess))
