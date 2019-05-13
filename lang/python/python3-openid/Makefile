#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=python3-openid
PKG_VERSION:=3.1.0
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=Eneas U de Queiroz <cote2004-github@yahoo.com>

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://files.pythonhosted.org/packages/source/p/python3-openid
PKG_HASH:=628d365d687e12da12d02c6691170f4451db28d6d68d050007e4a40065868502
#PKG_BUILD_DIR:=$(BUILD_DIR)/python3-openid-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include ../python3-package.mk

PYTHON3_PKG_SETUP_ARGS:=

define Package/python3-openid
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Python3 OpenID library
  URL:=https://github.com/necaris/python3-openid
  DEPENDS:= +python3-light
  VARIANT:=python3
endef

define Package/python-openid/description
  This is a set of Python packages to support use of the OpenID
  decentralized identity system in your application, update to Python 3.
endef

$(eval $(call Py3Package,python3-openid))
$(eval $(call BuildPackage,python3-openid))
$(eval $(call BuildPackage,python3-openid-src))
