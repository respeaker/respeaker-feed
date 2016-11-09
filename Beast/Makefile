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

PKG_NAME:=beast
PKG_VERSION:=1.0.0-b18
PKG_RELEASE:=$(PKG_SOURCE_VERSION)

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/vinniefalco/Beast
PKG_SOURCE_SUBDIR:=$(PKG_NAME)
PKG_SOURCE_VERSION=7b4de4b9513105845181321ba672bea4ce4a9062
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz
PKG_MAINTAINER:=Baozhu Zuo <zuobaozhu@gmail.com>


#PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_DEPENDS:=+libstdcpp +libpthread +boost-libs


include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk
define Package/beast
	SECTION:=utils
	CATEGORY:=ReSpeaker
	TITLE:=HTTP and WebSocket implementations built on Boost.Asio in C++11
	DEPENDS:=+libstdcpp +libpthread +boost-libs
endef

#define Package/beast/install
#endef

$(eval $(call BuildPackage,beast))
