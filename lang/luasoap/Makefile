#
# Copyright (C) 2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luasoap
PKG_VERSION:=3_0_1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/tomasguisasola/luasoap/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=0a57606797649992f43b3433f0eb04df7787ecdfdcf9403de71f278147ce96b5

PKG_MAINTAINER:=Liu Peng <pengliu@credosemi.com>
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/luasoap
  SUBMENU:=Lua
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=LuaSOAP
  URL:=https://github.com/tomasguisasola/luasoap
  DEPENDS:=+lua +luaexpat +luasec +luasocket
endef

define Package/luasoap/description
  LuaSOAP is a library of functions to deal with SOAP.
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luasoap/install
	$(INSTALL_DIR) $(1)/usr/lib/lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/soap.lua $(1)/usr/lib/lua/
	$(INSTALL_DIR) $(1)/usr/lib/lua/soap
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/{client,server}.lua $(1)/usr/lib/lua/soap/
	$(INSTALL_DIR) $(1)/usr/lib/lua/soap/client
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/src/client/https.lua $(1)/usr/lib/lua/soap/client/
	$(INSTALL_DIR) $(1)/usr/lib/lua/soap/tests
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/tests/test{,-http,-server}.lua $(1)/usr/lib/lua/soap/tests/
endef

$(eval $(call BuildPackage,luasoap))
