#
# Copyright (C) 2007-2018 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=mysqlclient
PKG_VERSION:=1.3.12
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://files.pythonhosted.org/packages/source/m/$(PKG_NAME)
PKG_HASH:=2d9ec33de39f4d9c64ad7322ede0521d85829ce36a76f9dd3d6ab76a9c8648e5

include $(INCLUDE_DIR)/package.mk
include ../python-package.mk

define Package/python-mysql
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=MySQL database adapter for Python
  URL:=https://pypi.python.org/project/mysqlclient
  MAINTAINER:=Gergely Kiss <mail.gery@gmail.com>
  DEPENDS:=+python +libmysqlclient
endef

define Package/python-mysql/description
 MySQLdb is an thread-compatible interface to the popular MySQL database
 server that provides the Python database API.
endef

define Build/Compile
	$(call Build/Compile/PyMod,,install --prefix=/usr --root=$(PKG_INSTALL_DIR))
endef

define Package/python-mysql/install
	$(INSTALL_DIR) $(1)$(PYTHON_PKG_DIR)
	$(CP) \
	    $(PKG_INSTALL_DIR)$(PYTHON_PKG_DIR)/* \
	    $(1)$(PYTHON_PKG_DIR)
endef

$(eval $(call BuildPackage,python-mysql))
