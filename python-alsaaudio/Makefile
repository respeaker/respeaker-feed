#
# Copyright (c) 2016 Seeed Technology Limited.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-alsaaudio
PKG_VERSION:=0.8.2
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/larsimmisch/pyalsaaudio.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=74d9e7d6e1b04238a679bb8349432cddc58eb2c7
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

# PKG_BUILD_DIR:=$(BUILD_DIR)/pyalsaaudio-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=python python-setuptools alsa-lib

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-alsaaudio
  SECTION:=respeaker
  CATEGORY:=ReSpeaker
  TITLE:=python-alsaaudio
  URL:=https://github.com/larsimmisch/pyalsaaudio
  DEPENDS:=+python +alsa-lib
endef

define Package/python-alsaaudio/description
	ALSA wrappers for Python
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix="$(PKG_INSTALL_DIR)/usr")
endef

define Package/python-alsaaudio/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) $(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
	     $(1)$(PYTHON_PKG_DIR)
endef

$(eval $(call BuildPackage,python-alsaaudio))
