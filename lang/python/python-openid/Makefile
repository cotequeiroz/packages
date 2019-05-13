#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python-openid
PKG_VERSION:=2.2.5
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=Eneas U de Queiroz <cote2004-github@yahoo.com>

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://files.pythonhosted.org/packages/source/p/python-openid
PKG_HASH:=92c51c3ecec846cbec4aeff11f9ff47303d4a63f93b0e6ac0ec02a091fed70ef

include $(INCLUDE_DIR)/package.mk
include ../python-package.mk

PYTHON_PKG_SETUP_ARGS:=

define Package/python-openid
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Python2 OpenID library
  URL:=https://github.com/openid/python-openid
  DEPENDS:= +python-light
  VARIANT:=python
endef

define Package/python-openid/description
  This is a set of Python packages to support use of the OpenID
  decentralized identity system in your application.
endef

$(eval $(call PyPackage,python-openid))
$(eval $(call BuildPackage,python-openid))
$(eval $(call BuildPackage,python-openid-src))
