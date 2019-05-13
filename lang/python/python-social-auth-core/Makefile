#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-social-auth-core
PKG_VERSION:=3.1.0
PKG_RELEASE:=1
PKG_LICENSE:=BSD-3-Clause

PKG_SOURCE:=social-auth-core-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://files.pythonhosted.org/packages/source/s/social-auth-core
PKG_HASH:=cc871fb4528f7cbba67efdba0bc0f7d7c6eeb92113b0cdc9368dd91ffe965782
PKG_BUILD_DIR:=$(BUILD_DIR)/$(BUILD_VARIANT)-social-auth-core-$(PKG_VERSION)
PKG_MAINTAINER:=Eneas U de Queiroz <cote2004-github@yahoo.com>

include $(INCLUDE_DIR)/package.mk
include ../python-package.mk
include ../python3-package.mk

PKG_UNPACK:=$(HOST_TAR) -C $(PKG_BUILD_DIR) --strip-components=1 -xzf $(DL_DIR)/$(PKG_SOURCE)

define Package/python-social-auth-core/Default
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  URL:=https://github.com/python-social-auth/social-core
endef

define Package/python-social-auth-core
$(call Package/python-social-auth-core/Default)
  TITLE:=Social authentication/registration mechanism for Python
  DEPENDS:= \
	  +PACKAGE_python-social-auth-core:python-light \
	  +PACKAGE_python-social-auth-core:python-oauthlib \
	  +PACKAGE_python-social-auth-core:python-openid \
	  +PACKAGE_python-social-auth-core:python-pyjwt \
	  +PACKAGE_python-social-auth-core:python-requests \
	  +PACKAGE_python-social-auth-core:python-requests-oauthlib \
	  +PACKAGE_python-social-auth-core:python-six \
	  +PACKAGE_python-social-auth-core:python-xml
  VARIANT:=python
endef

define Package/python3-social-auth-core
$(call Package/python-social-auth-core/Default)
  TITLE:=Social authentication/registration mechanism for Python3
  DEPENDS:= \
	  +PACKAGE_python3-social-auth-core:python3-light \
	  +PACKAGE_python3-social-auth-core:python3-defusedxml \
	  +PACKAGE_python3-social-auth-core:python3-oauthlib \
	  +PACKAGE_python3-social-auth-core:python3-openid \
	  +PACKAGE_python3-social-auth-core:python3-pyjwt \
	  +PACKAGE_python3-social-auth-core:python3-requests \
	  +PACKAGE_python3-social-auth-core:python3-requests-oauthlib \
	  +PACKAGE_python3-social-auth-core:python3-six \
	  +PACKAGE_python3-social-auth-core:python3-xml
  VARIANT:=python3
endef

define Package/python-social-auth-core/description
  Python Social Auth is an easy to setup social authentication/registration mechanism
  with support for several frameworks and auth providers.

  This is the core component of the python-social-auth ecosystem, it implements the
  common interface to define new authentication backends to third parties services,
  implement integrations with web frameworks and storage solutions.
endef

define Package/python3-social-auth-core/description
$(call Package/python-social-auth-core/description)
.
(Variant for Python3)
endef

$(eval $(call PyPackage,python-social-auth-core))
$(eval $(call BuildPackage,python-social-auth-core))
$(eval $(call BuildPackage,python-social-auth-core-src))

$(eval $(call Py3Package,python3-social-auth-core))
$(eval $(call BuildPackage,python3-social-auth-core))
$(eval $(call BuildPackage,python3-social-auth-core-src))
