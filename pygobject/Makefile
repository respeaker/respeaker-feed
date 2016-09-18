#
# Copyright (C) 2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=pygobject
# PKG_VERSION:=2.21.5
PKG_VERSION:=3.14.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.xz
# PKG_SOURCE_URL:=@GNOME/$(PKG_NAME)/2.21
PKG_SOURCE_URL:=@GNOME/$(PKG_NAME)/3.14
# PKG_MD5SUM:=77ad7e8dbf13188364c9f56f907e530a
PKG_MD5SUM:=17722912afa982a6feace4bb9bf52778
# PKG_FIXUP:=autoreconf
# PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/nls.mk
$(call include_mk, python-package.mk)

# EXTRA_LDFLAGS+= \
	# -L$(ICONV_PREFIX) -L$(INTL_PREFIX)

# TARGET_CFLAGS += $(FPIC)
CONFIGURE_ARGS += --enable-static --enable-shared --disable-cairo --with-python=python2

define Package/python-gi
  SECTION:=respeaker
  CATEGORY:=ReSpeaker
  TITLE:=GLib bindings for python
  URL:=http://www.pygtk.org/
  DEPENDS:=+python +glib2 +libffi +libgirepository
endef

define Package/python-gi/description
  GLib bindings for python
endef

# define Build/Configure
	# $(call Build/Configure/Default, \
		# --with-libffi --disable-cairo \
	# )
# endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include/pygobject-3.0
	$(CP) $(PKG_BUILD_DIR)/gi/pygobject.h $(1)/usr/include/pygobject-3.0
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_BUILD_DIR)/pygobject-3.0.pc $(1)/usr/lib/pkgconfig
endef

define Package/python-gi/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)/gi
	$(CP) $(PKG_BUILD_DIR)/gi/.libs/_gi.so \
		$(1)$(PYTHON_PKG_DIR)/gi
	$(CP) $(PKG_BUILD_DIR)/gi/*.py \
		$(1)$(PYTHON_PKG_DIR)/gi
	$(foreach d,overrides _gobject repository, \
		$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)/gi/$(d); \
		$(CP) $(PKG_BUILD_DIR)/gi/$(d)/*.py \
			$(1)$(PYTHON_PKG_DIR)/gi/$(d); \
	)
endef

$(eval $(call BuildPackage,python-gi))
