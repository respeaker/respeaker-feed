#
# Copyright (C) 2016 Seeed Technology Limited.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=terminado
PKG_VERSION:=0.6
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/takluyver/terminado.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz
PKG_BUILD_DEPENDS:=+python

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/terminado
	SECTION:=respeaker
	CATEGORY:=ReSpeaker
	TITLE:=terminado
	URL:=https://github.com/takluyver/terminado
	DEPENDS:=+python +ptyprocess
endef

define Package/terminado/description
	Terminals served by tornado websockets
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

define Package/terminado/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)/
	$(CP) \
		$(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
		$(1)$(PYTHON_PKG_DIR)/
endef

$(eval $(call BuildPackage,terminado))
