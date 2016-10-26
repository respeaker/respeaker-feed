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

PKG_NAME:=fasterconfig
PKG_VERSION:=0.0.4
PKG_RELEASE:=$(PKG_SOURCE_VERSION)

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/respeaker/FasterConfig.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)
PKG_SOURCE_VERSION:=0e162f5bf589a51f56b8d4a44f7264a2e9d4f05f
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz
PKG_MAINTAINER:=Baozhu Zuo <zuobaozhu@gmail.com>


#PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_DEPENDS:=+libstdcpp +libpthread


include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk
define Package/fasterconfig
	SECTION:=utils
	CATEGORY:=ReSpeaker
	TITLE:=More faster way to setup wifi 
	DEPENDS:=+libstdcpp +libpthread
endef

define Package/fasterconfig/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/src/fasterconfig $(1)/usr/bin/
	mkdir -p $(1)/etc/fasterconfig
	$(CP) ./files/etc/fasterconfig/fasterconfig.conf $(1)/etc/fasterconfig/fasterconfig.conf
	$(CP) $(PKG_BUILD_DIR)/fasterconfig-msg.html $(1)/etc/fasterconfig
	$(INSTALL_DIR) $(1)/etc/init.d	
	$(INSTALL_BIN) ./files/etc/init.d/fasterconfig $(1)/etc/init.d/fasterconfig
endef

$(eval $(call BuildPackage,fasterconfig))
