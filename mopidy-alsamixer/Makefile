#
# Copyright (C) 2016 Seeed Technology Limited.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=mopidy-alsamixer
PKG_VERSION:=v1.0.3
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/mopidy/mopidy-alsamixer.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz
PKG_BUILD_DEPENDS:=+python +mopidy +python-alsaaudio

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/mopidy-alsamixer
	SECTION:=respeaker
	CATEGORY:=ReSpeaker
	TITLE:=mopidy-alsamixer
	URL:=https://github.com/mopidy/mopidy-alsamixer.git
	DEPENDS:=+python +mopidy +python-alsaaudio
endef

define Package/mopidy-alsamixer/description
	Mopidy extension for ALSA volume control
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

define Package/mopidy-alsamixer/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)/
	$(CP) \
		$(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
		$(1)$(PYTHON_PKG_DIR)/
endef

$(eval $(call BuildPackage,mopidy-alsamixer))
