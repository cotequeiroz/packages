#
# Copyright (C) 2007-2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-requests-oauthlib
PKG_VERSION:=1.2.0
PKG_RELEASE:=1
PKG_LICENSE:=ISC
PKG_MAINTAINER:=Eneas U de Queiroz <cote2004-github@yahoo.com>

PKG_SOURCE:=requests-oauthlib-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://files.pythonhosted.org/packages/source/r/requests-oauthlib
PKG_HASH:=bd6533330e8748e94bf0b214775fed487d309b8b8fe823dc45641ebcd9a32f57
PKG_BUILD_DIR:=$(BUILD_DIR)/$(BUILD_VAIRANT)/requests-oauthlib-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include ../python-package.mk
include ../python3-package.mk

PKG_UNPACK:=$(HOST_TAR) -C $(PKG_BUILD_DIR) --strip-components=1 -xzf $(DL_DIR)/$(PKG_SOURCE)

define Package/python-requests-oauthlib/Default
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  URL:=https://github.com/requests/requests-oauthlib
endef

define Package/python-requests-oauthlib
  $(call Package/python-requests-oauthlib/Default)
  TITLE:=OAuthlib authentication support for Requests for Python
  DEPENDS:= \
	+PACKAGE_python-requests-oauthlib:python-light \
	+PACKAGE_python-requests-oauthlib:python-requests \
	+PACKAGE_python-requests-oauthlib:python-oauthlib \
	+PACKAGE_python-requests-oauthlib:python-cryptography \
	+PACKAGE_python-requests-oauthlib:python-pyjwt
  VARIANT:=python
endef

define Package/python3-requests-oauthlib
  $(call Package/python-requests-oauthlib/Default)
  TITLE:=OAuthlib authentication support for Requests for Python3
  DEPENDS:= \
	+PACKAGE_python3-requests-oauthlib:python3-light \
	+PACKAGE_python3-requests-oauthlib:python3-requests \
	+PACKAGE_python3-requests-oauthlib:python3-oauthlib \
	+PACKAGE_python3-requests-oauthlib:python3-cryptography \
	+PACKAGE_python3-requests-oauthlib:python3-pyjwt
  VARIANT:=python3
endef

define Package/python-requests-oauthlib/description
  This project provides first-class OAuth library support for Requests.
endef

define Package/python3-requests-oauthlib/description
$(call Package/python-social-auth-core/description)
.
(Variant for Python3)
endef

$(eval $(call PyPackage,python-requests-oauthlib))
$(eval $(call BuildPackage,python-requests-oauthlib))
$(eval $(call BuildPackage,python-requests-oauthlib-src))

$(eval $(call Py3Package,python3-requests-oauthlib))
$(eval $(call BuildPackage,python3-requests-oauthlib))
$(eval $(call BuildPackage,python3-requests-oauthlib-src))
