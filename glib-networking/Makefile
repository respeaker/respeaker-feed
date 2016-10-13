#
# 
#


include $(TOPDIR)/rules.mk

PKG_NAME:=glib-networking
PKG_VERSION:=2.40.0
PKG_RELEASE=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.xz
PKG_SOURCE_URL:=http://ftp.gnome.org/pub/gnome/sources/glib-networking/2.50/
PKG_MD5SUM:=94a1ceb1dc50adcc29b1ebba919c87a1

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/glib-networking
  SECTION:=respeaker
  CATEGORY:=ReSpeaker
  DEPENDS:=+glib2 +libintl-stub +libgnutls +libproxy
  TITLE:=glib-networking
endef

define Package/glib-networking/description
  glib-networking
endef

# define Build/Prepare
	# mkdir -p $(PKG_BUILD_DIR)
	# $(CP) ./src/* $(PKG_BUILD_DIR)/
# endef

TARGET_CFLAGS+=-I$(STAGING_DIR)/usr/lib/libintl-stub/include

CONFIGURE_ARGS+= \
	--disable-static \
	--without-pkcs11 \
	--with-libproxy  \
	--disable-dependency-tracking
	
# TARGET_CFLAGS += -ggdb3


define Package/glib-networking/install
	$(INSTALL_DIR) $(1)/usr/lib/gio/modules
	$(CP) $(PKG_BUILD_DIR)/tls/gnutls/.libs/libgiognutls.so $(1)/usr/lib/gio/modules
endef

$(eval $(call BuildPackage,glib-networking))
