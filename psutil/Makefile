#
# Copyright (C) 2016 Seeed Technology Limited.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=psutil
PKG_VERSION:=release-5.0.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/giampaolo/psutil.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_SOURCE_VERSION).tar.gz
PKG_BUILD_DEPENDS:=+python 

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/psutil
	SECTION:=respeaker
	CATEGORY:=ReSpeaker
	TITLE:=psutil
	URL:=https://github.com/giampaolo/psutil
	DEPENDS:=+python
endef

define Package/psutil/description
	A cross-platform process and system utilities module for Python
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

define Package/psutil/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)/
	$(CP) \
		$(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
		$(1)$(PYTHON_PKG_DIR)/
endef

$(eval $(call BuildPackage,psutil))
