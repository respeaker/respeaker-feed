#
# Copyright (C) 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=juci-lighttpd
PKG_RELEASE:=2

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/mkschreder/juci-lighttpd.git
PKG_SOURCE_VERSION:=23644e8f150baac0aa5199a6820234d8e7898231
PKG_VERSION:=1.4.33
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_SOURCE_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_SOURCE_VERSION).tar.gz
PKG_MAINTAINER:=Martin Schröder <mkschreder.uk@gmail.com>
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/juci-lighttpd/Default
  SUBMENU:=Web Servers/Proxies
  SECTION:=net
  CATEGORY:=Network
  URL:=http://www.lighttpd.net/
  MAINTAINER:=W. Michael Petullo <mike@flyn.org>
endef

define Package/juci-lighttpd
  $(call Package/juci-lighttpd/Default)
  MENU:=1
  DEPENDS:=+LIGHTTPD_SSL:libopenssl +libpcre +libpthread
  TITLE:=Lighttpd with websocket support (otherwise the same as default)
endef

define Package/juci-lighttpd/config
config LIGHTTPD_SSL
	bool "SSL support"
	depends on PACKAGE_juci-lighttpd
	default y
	help
	  Implements SSL support in juci-lighttpd (using libopenssl). This
	  option is required if you enable the SSL engine in your
	  juci-lighttpd confguration file.
endef
 
define Package/juci-lighttpd-mod-websocket
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Websockets module
endef

define Package/juci-lighttpd-mod-access
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Access restrictions module
endef

define Package/juci-lighttpd-mod-accesslog
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Access logging module
endef

define Package/juci-lighttpd-mod-alias
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Directory alias module
endef

define Package/juci-lighttpd-mod-auth
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Authentication module
endef

define Package/juci-lighttpd-mod-cgi
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=CGI module
endef

define Package/juci-lighttpd-mod-cml
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Cache Meta Language module
endef

define Package/juci-lighttpd-mod-compress
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd +zlib
  TITLE:=Compress output module
endef

define Package/juci-lighttpd-mod-evasive
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Evasive module
endef

define Package/juci-lighttpd-mod-evhost
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Exnhanced Virtual-Hosting module
endef

define Package/juci-lighttpd-mod-expire
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Expire module
endef

define Package/juci-lighttpd-mod-extforward
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Extract client IP module
endef

define Package/juci-lighttpd-mod-fastcgi
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=FastCGI module
endef

define Package/juci-lighttpd-mod-flv-streaming
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=flv streaming module
endef

define Package/juci-lighttpd-mod-magnet
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=magnet module
endef

define Package/juci-lighttpd-mod-mysql-vhost
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd +libmysqlclient
  TITLE:=Mysql virtual hosting module
endef

define Package/juci-lighttpd-mod-proxy
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Proxy module
endef

define Package/juci-lighttpd-mod-redirect
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd +libpcre
  TITLE:=URL redirection module
endef

define Package/juci-lighttpd-mod-rewrite
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd +libpcre
  TITLE:=URL rewriting module
endef

define Package/juci-lighttpd-mod-rrdtool
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=rrdtool module
endef

define Package/juci-lighttpd-mod-scgi
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=SCGI module
endef

define Package/juci-lighttpd-mod-secdownload
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Secure and fast download module
endef

define Package/juci-lighttpd-mod-setenv
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Environment variable setting module
endef

define Package/juci-lighttpd-mod-simple-vhost
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Simple virtual hosting module
endef

define Package/juci-lighttpd-mod-ssi
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd +libpcre
  TITLE:=SSI module
endef

define Package/juci-lighttpd-mod-status
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=Server status display module
endef

define Package/juci-lighttpd-mod-trigger-b4-dl
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd +libpcre
  TITLE:=Trigger before download module
endef

define Package/juci-lighttpd-mod-userdir
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=User directory module
endef

define Package/juci-lighttpd-mod-usertrack
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd
  TITLE:=User tracking module
endef

define Package/juci-lighttpd-mod-webdav
  $(call Package/juci-lighttpd/Default)
  DEPENDS:=+juci-lighttpd +libsqlite3 +libuuid +libxml2
  TITLE:=WebDAV module
endef

CONFIGURE_ARGS+= \
	--libdir=/usr/lib/lighttpd \
	--sysconfdir=/etc/lighttpd \
	--enable-shared \
	--enable-static \
	--disable-rpath \
	--without-attr \
	--without-bzip2 \
	--without-fam \
	--without-gdbm \
	--without-ldap \
	--without-lua \
	--without-memcache \
	--without-mysql \
	--with-pcre \
	--without-valgrind \
	 $(call autoconf_bool,CONFIG_IPV6,ipv6)

CONFIGURE_VARS+= \
	PCRE_LIB="-lpcre" \

ifneq ($(strip $(CONFIG_LIGHTTPD_SSL)),)
  CONFIGURE_ARGS+= \
	--with-openssl="$(STAGING_DIR)/usr"
else
  CONFIGURE_ARGS+= \
	--without-openssl
endif
 
ifneq ($(SDK)$(CONFIG_PACKAGE_juci-lighttpd-mod-websocket),)
  CONFIGURE_ARGS+= \
	--with-websocket=ALL \
        --with-libicu=no
endif

ifneq ($(SDK)$(CONFIG_PACKAGE_juci-lighttpd-mod-webdav),)
  CONFIGURE_ARGS+= \
	--with-webdav-locks \
	--with-webdav-props
  # XXX: needed by sqlite3 to prevent segfaults in mod_webdav.so
  CONFIGURE_VARS+= \
	LIBS="-lpthread"
else
  CONFIGURE_ARGS+= \
	--without-webdav-locks \
	--without-webdav-props
endif

define Build/Configure
$(call Build/Configure/Default)
	# XXX: override pcre (mis)detection by ./configure when cross-compiling
	echo "#define HAVE_LIBPCRE 1" >>$(PKG_BUILD_DIR)/config.h
	echo "#define HAVE_PCRE_H 1" >>$(PKG_BUILD_DIR)/config.h
endef

define Package/juci-lighttpd/conffiles
/etc/lighttpd/lighttpd.conf
endef

define Package/juci-lighttpd/install
	$(INSTALL_DIR) $(1)/etc/lighttpd
	$(CP) ./files/etc/* $(1)/etc/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/lighttpd.init $(1)/etc/init.d/lighttpd
	$(INSTALL_DIR) $(1)/usr/lib/lighttpd
	for m in dirlisting indexfile staticfile; do \
		$(CP) $(PKG_INSTALL_DIR)/usr/lib/lighttpd/mod_$$$${m}.so $(1)/usr/lib/lighttpd/ ; \
	done
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/lighttpd $(1)/usr/sbin/
endef

define BuildPlugin
  define Package/$(1)/install
	[ -z "$(2)" ] || $(INSTALL_DIR) $$(1)/usr/lib/lighttpd
	for m in $(2); do \
		$(CP) $(PKG_INSTALL_DIR)/usr/lib/lighttpd/mod_$$$$$$$${m}.so $$(1)/usr/lib/lighttpd/ ; \
	done
  endef

  $$(eval $$(call BuildPackage,$(1)))
endef

$(eval $(call BuildPackage,juci-lighttpd))
$(eval $(call BuildPlugin,juci-lighttpd-mod-access,access))
$(eval $(call BuildPlugin,juci-lighttpd-mod-accesslog,accesslog))
$(eval $(call BuildPlugin,juci-lighttpd-mod-alias,alias))
$(eval $(call BuildPlugin,juci-lighttpd-mod-auth,auth))
$(eval $(call BuildPlugin,juci-lighttpd-mod-cgi,cgi))
$(eval $(call BuildPlugin,juci-lighttpd-mod-cml,cml))
$(eval $(call BuildPlugin,juci-lighttpd-mod-compress,compress))
$(eval $(call BuildPlugin,juci-lighttpd-mod-evasive,evasive))
$(eval $(call BuildPlugin,juci-lighttpd-mod-evhost,evhost))
$(eval $(call BuildPlugin,juci-lighttpd-mod-expire,expire))
$(eval $(call BuildPlugin,juci-lighttpd-mod-extforward,extforward))
$(eval $(call BuildPlugin,juci-lighttpd-mod-fastcgi,fastcgi))
$(eval $(call BuildPlugin,juci-lighttpd-mod-flv-streaming,flv_streaming))
$(eval $(call BuildPlugin,juci-lighttpd-mod-magnet,magnet))
$(eval $(call BuildPlugin,juci-lighttpd-mod-proxy,proxy))
$(eval $(call BuildPlugin,juci-lighttpd-mod-redirect,redirect))
$(eval $(call BuildPlugin,juci-lighttpd-mod-rewrite,rewrite))
$(eval $(call BuildPlugin,juci-lighttpd-mod-rrdtool,rrdtool))
$(eval $(call BuildPlugin,juci-lighttpd-mod-scgi,scgi))
$(eval $(call BuildPlugin,juci-lighttpd-mod-secdownload,secdownload))
$(eval $(call BuildPlugin,juci-lighttpd-mod-setenv,setenv))
$(eval $(call BuildPlugin,juci-lighttpd-mod-simple-vhost,simple_vhost))
$(eval $(call BuildPlugin,juci-lighttpd-mod-ssi,ssi))
$(eval $(call BuildPlugin,juci-lighttpd-mod-status,status))
$(eval $(call BuildPlugin,juci-lighttpd-mod-trigger-b4-dl,trigger_b4_dl))
$(eval $(call BuildPlugin,juci-lighttpd-mod-userdir,userdir))
$(eval $(call BuildPlugin,juci-lighttpd-mod-usertrack,usertrack))
$(eval $(call BuildPlugin,juci-lighttpd-mod-webdav,webdav))
$(eval $(call BuildPlugin,juci-lighttpd-mod-websocket,websocket))
