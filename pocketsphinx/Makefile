#
# Copyright (c) 2016 Seeed Technology Limited.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=pocketsphinx
PKG_VERSION:=5prealpha
PKG_RELEASE=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://downloads.sourceforge.net/project/cmusphinx/pocketsphinx/5prealpha/
PKG_MD5SUM:=2c4fb3a1318bb2470997ab7eb98ef69a

# PKG_SOURCE_PROTO:=git
# PKG_SOURCE_URL:=https://github.com/cmusphinx/pocketsphinx.git
# PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
# PKG_SOURCE_VERSION:=ec89abd9d2e976019338ecae7d6cafeecdb95eb2
# PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

# PKG_FIXUP:=autoreconf
# PKG_INSTALL=1
PKG_BUILD_DEPENDS:=sphinxbase


include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/pocketsphinx
  SECTION:=respeaker
  CATEGORY:=ReSpeaker
  DEPENDS:=+sphinxbase
  TITLE:=PocketSphinx
endef

define Package/pocketsphinx/description
  PocketSphinx is one of Carnegie Mellon University's open source large vocabulary,  speaker-independent continuous speech recognition engine.
endef

CONFIGURE_ARGS+= \
	--enable-fixed \
	# --without-python

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/pocketsphinx
	$(CP) $(PKG_BUILD_DIR)/include/*.h $(1)/usr/include/pocketsphinx
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/src/libpocketsphinx/.libs/*.{a,so*} $(PKG_BUILD_DIR)/src/libpocketsphinx/libpocketsphinx.la $(1)/usr/lib
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_BUILD_DIR)/pocketsphinx.pc $(1)/usr/lib/pkgconfig
	$(INSTALL_DIR) $(1)/usr/share/pocketsphinx/swig
	$(CP) $(PKG_BUILD_DIR)/swig/*.i $(1)/usr/share/pocketsphinx/swig
endef

define Package/pocketsphinx/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/src/libpocketsphinx/.libs/*.so*  $(1)/usr/lib
	# $(INSTALL_DIR) $(1)/usr/bin
	#$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/programs/.libs/pocketsphinx_continuous $(1)/usr/bin
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)/pocketsphinx
	$(CP) $(PKG_BUILD_DIR)/swig/python/*.py $(1)$(PYTHON_PKG_DIR)/pocketsphinx
	$(CP) $(PKG_BUILD_DIR)/swig/python/.libs/_pocketsphinx.so.0.0.0 $(1)$(PYTHON_PKG_DIR)/pocketsphinx/_pocketsphinx.so
endef

$(eval $(call BuildPackage,pocketsphinx))
