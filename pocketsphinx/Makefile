#
# 
#


include $(TOPDIR)/rules.mk

PKG_NAME:=pocketsphinx
PKG_VERSION:=5prealpha
PKG_RELEASE=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_DEPENDS:=sphinxbase

include $(INCLUDE_DIR)/package.mk

define Package/pocketsphinx
  SECTION:=sound
  CATEGORY:=Sound
  DEPENDS:=+sphinxbase
  TITLE:=pocketsphinx
endef

define Package/pocketsphinx/description
  pocketsphinx
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

CONFIGURE_ARGS+= \
	--without-python
	
# TARGET_CFLAGS += -ggdb3
	
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
	$(INSTALL_DIR) $(1)/usr/bin
	#$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/programs/.libs/pocketsphinx_continuous $(1)/usr/bin

endef

$(eval $(call BuildPackage,pocketsphinx))
