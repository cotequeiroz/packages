#
# Copyright (C) 2016 Amnon Paz <pazamnon@gmail.com>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=lua-openssl
PKG_VERSION:=0.7.3
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/zhaozg/lua-openssl/tar.gz/$(PKG_VERSION)?
PKG_HASH:=d0eb26510ba4d44d69504b49d58323e093788188297910a2f72c5d761a37ca6d

PKG_MAINTAINER:=Amnon Paz <pazamnon@gmail.com>
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/lua-openssl
  SUBMENU:=Lua
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Lua openSSL binding
  URL:=https://github.com/zhaozg/lua-openssl
  DEPENDS:=+lua +libopenssl +librt +luajit
endef

define Package/lua-openssl/description
    A free, MIT-licensed OpenSSL binding for Lua.
endef

define Package/lua-openssl/install
	$(INSTALL_DIR) $(1)/usr/lib/lua
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/openssl.so $(1)/usr/lib/lua/
endef

$(eval $(call BuildPackage,lua-openssl))
