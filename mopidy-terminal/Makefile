#
# Copyright (C) 2016 Seeed Technology Limited.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=mopidy-terminal
PKG_VERSION:=v0.1.1
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/xiongyihui/mopidy-terminal.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz
PKG_BUILD_DEPENDS:=+python +mopidy

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/mopidy-terminal
	SECTION:=respeaker
	CATEGORY:=ReSpeaker
	TITLE:=mopidy-terminal
	URL:=https://github.com/xiongyihui/mopidy-terminal
	DEPENDS:=+python +terminado
endef

define Package/mopidy-terminal/description
	Web terminal
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

define Package/mopidy-terminal/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)/
	$(CP) \
		$(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
		$(1)$(PYTHON_PKG_DIR)/
endef

$(eval $(call BuildPackage,mopidy-terminal))
