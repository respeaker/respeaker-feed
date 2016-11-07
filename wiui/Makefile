#2016 Copyright (c) Seeed Technology Inc.  All right reserved.
#	Author:Baozhu Zuo
#	Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#THE SOFTWARE.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=wiui
PKG_VERSION:=0.0.2
PKG_RELEASE:=$(PKG_SOURCE_VERSION)

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/respeaker/wiui.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)
PKG_SOURCE_VERSION:=fb88cf08282d0c3533142e1da0bee589c072c47e
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz
PKG_MAINTAINER:=Baozhu Zuo <zuobaozhu@gmail.com>

PKG_FIXUP:=autoreconf

#PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_DEPENDS:=+libncurses +libpthread


include $(INCLUDE_DIR)/package.mk

define Package/wiui
	SECTION:=respeaker
	CATEGORY:=ReSpeaker
	TITLE:=show wifi config on terminal
	DEPENDS:=+libncurses +libpthread
endef
define Package/wiui/install
	 $(INSTALL_DIR) $(1)/usr/bin
	 $(CP) $(PKG_BUILD_DIR)/src/wiui $(1)/usr/bin
	 $(CP) $(PKG_BUILD_DIR)/src/wictl $(1)/usr/bin
endef

$(eval $(call BuildPackage,wiui))
