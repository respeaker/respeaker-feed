#
# Copyright (c) 2016 Seeed Technology Limited.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-webrtcvad
PKG_VERSION:=2.0.8
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/wiseman/py-webrtcvad.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=143d1b016f4520103649a9709274166368377291
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_BUILD_DEPENDS:=python python-setuptools

include $(INCLUDE_DIR)/package.mk
$(call include_mk, python-package.mk)

define Package/python-webrtcvad
  SECTION:=Python
  CATEGORY:=ReSpeaker
  TITLE:=Python interface to the WebRTC Voice Activity Detector
  URL:=https://github.com/wiseman/py-webrtcvad
  DEPENDS:=+python
endef

define Package/python-webrtcvad/description
  This is a python interface to the WebRTC Voice Activity Detector (VAD). 
  It is compatible with Python 2 and Python 3. A VAD classifies a piece of
  audio data as being voiced or unvoiced. It can be useful for telephony
  and speech recognition. The VAD that Google developed for the WebRTC
  project is reportedly one of the best available, being fast, modern and free.
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix="$(PKG_INSTALL_DIR)/usr")
endef

define Package/python-webrtcvad/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) $(PKG_BUILD_DIR)/webrtcvad.egg-info/PKG-INFO $(1)$(PYTHON_PKG_DIR)/webrtcvad.egg-info
	$(CP) $(PKG_BUILD_DIR)/build/lib.linux2-2.7/* $(1)$(PYTHON_PKG_DIR)
endef

$(eval $(call BuildPackage,python-webrtcvad))
