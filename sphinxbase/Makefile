#
# 
#


include $(TOPDIR)/rules.mk

PKG_NAME:=sphinxbase
PKG_VERSION:=5prealpha
PKG_RELEASE=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_DEPENDS:=alsa-lib

include $(INCLUDE_DIR)/package.mk

define Package/sphinxbase
  SECTION:=sound
  CATEGORY:=Sound
  DEPENDS:=+alsa-lib
  TITLE:=sphinxbase
endef

define Package/sphinxbase/description
  sphinxbase
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

CONFIGURE_ARGS+= \
	--without-lapack \
	--enable-fixed \
	--without-python

	# --enable-debug
	
# TARGET_CFLAGS += -ggdb3
	
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
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/src/libsphinxad/.libs/*.so* $(1)/usr/lib
endef

$(eval $(call BuildPackage,sphinxbase))
