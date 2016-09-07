#
# Copyright (c) 2016 Seeed Technology Limited.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=sphinxbase
PKG_VERSION:=5prealpha
PKG_RELEASE=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/respeaker/sphinxbase.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=e6555e0f22c10d6411183bb451b6214248150d0b
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_FIXUP:=autoreconf
PKG_INSTALL=1
PKG_BUILD_DEPENDS:=alsa-lib

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/sphinxbase
  SECTION:=respeaker
  CATEGORY:=ReSpeaker
  DEPENDS:=+alsa-lib
  TITLE:=CMU Sphinx common libraries
endef

define Package/sphinxbase/description
  Sphinxbase contains the basic libraries shared by the CMU Sphinx trainer and all the Sphinx decoders (Sphinx-II, Sphinx-III, and PocketSphinx), as well as some common utilities for manipulating acoustic feature and audio files.
endef

CONFIGURE_ARGS+= \
	--without-lapack \
	--enable-fixed
	# --without-python

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/sphinxbase
	$(CP) $(PKG_BUILD_DIR)/include/sphinx_config.h $(1)/usr/include/sphinxbase
	$(CP) $(PKG_BUILD_DIR)/include/sphinxbase/*.h $(1)/usr/include/sphinxbase
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/src/libsphinxbase/.libs/*.{a,so*} $(PKG_BUILD_DIR)/src/libsphinxbase/libsphinxbase.la $(1)/usr/lib
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/src/libsphinxad/.libs/*.{a,so*} $(PKG_BUILD_DIR)/src/libsphinxad/libsphinxad.la $(1)/usr/lib
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_BUILD_DIR)/sphinxbase.pc $(1)/usr/lib/pkgconfig
	$(INSTALL_DIR) $(1)/usr/share/sphinxbase/swig
	$(CP) $(PKG_BUILD_DIR)/swig/*.i $(1)/usr/share/sphinxbase/swig
endef

define Package/sphinxbase/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/src/libsphinxbase/.libs/*.so* $(1)/usr/lib
	# $(CP) $(PKG_BUILD_DIR)/src/libsphinxad/.libs/*.so* $(1)/usr/lib
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)/sphinxbase
	$(CP) $(PKG_BUILD_DIR)/swig/python/*.py $(1)$(PYTHON_PKG_DIR)/sphinxbase
	$(CP) $(PKG_BUILD_DIR)/swig/python/.libs/_sphinxbase.so.0.0.0 $(1)$(PYTHON_PKG_DIR)/sphinxbase/_sphinxbase.so
endef

$(eval $(call BuildPackage,sphinxbase))
