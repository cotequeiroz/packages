#
# Copyright (C) 2006-2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=vpnc
PKG_REV:=550
PKG_VERSION:=0.5.3.r$(PKG_REV)
PKG_RELEASE:=10

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/streambinder/vpnc
PKG_SOURCE_VERSION:=024aa17a0a86716cac0db185b44bf07ba4f8c135
PKG_MIRROR_HASH:=c514aae6278d786ec105ef6b9289f620383d1201b6cd776b2c18c31b23cc709d

PKG_MAINTAINER:=Daniel Gimpelevich <daniel@gimpelevich.san-francisco.ca.us>
PKG_LICENSE:=VARIOUS
PKG_LICENSE_FILES:=COPYING

PKG_CONFIG_DEPENDS:= \
	CONFIG_VPNC_GNUTLS \
	CONFIG_VPNC_OPENSSL \


include $(INCLUDE_DIR)/package.mk

define Package/vpnc/config
	source "$(SOURCE)/Config.in"
endef

define Package/vpnc
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libgpg-error +libgcrypt +kmod-tun +VPNC_OPENSSL:libopenssl +VPNC_GNUTLS:libgnutls +vpnc-scripts +resolveip
  TITLE:=VPN client for Cisco EasyVPN
  URL:=http://www.unix-ag.uni-kl.de/~massar/vpnc/
  SUBMENU:=VPN
endef

define Package/vpnc/description
	A VPN client compatible with Cisco's EasyVPN equipment.

	Supports IPSec (ESP) with Mode Configuration and Xauth.  Supports only
	shared-secret IPSec authentication with Xauth, AES (256, 192, 128),
	3DES, 1DES, MD5, SHA1, DH1/2/5 and IP tunneling.
endef

define Package/vpnc/conffiles
/etc/vpnc/default.conf
endef

ifeq ($(CONFIG_VPNC_OPENSSL),y)
define Build/Compile
	$(call Build/Compile/Default, \
		OFLAGS="$(TARGET_CFLAGS)" \
		OS="Linux" VERSION="$(PKG_VERSION)" \
		STAGING_DIR="$(STAGING_DIR)" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		OPENSSL_GPL_VIOLATION=yes PREFIX=/usr \
		all install \
	)
endef
else
define Build/Compile
	$(call Build/Compile/Default, \
		OFLAGS="$(TARGET_CFLAGS)" \
		OS="Linux" VERSION="$(PKG_VERSION)" \
		STAGING_DIR="$(STAGING_DIR)" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		PREFIX=/usr \
		all install \
	)
endef
endif

define Package/vpnc/install
	$(INSTALL_DIR) $(1)/lib/netifd/proto
	$(INSTALL_BIN) ./files/vpnc.sh $(1)/lib/netifd/proto/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(CP)	$(PKG_INSTALL_DIR)/usr/sbin/vpnc \
		$(PKG_INSTALL_DIR)/usr/sbin/vpnc-disconnect \
		$(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/vpnc
	$(INSTALL_CONF) $(PKG_INSTALL_DIR)/etc/vpnc/default.conf $(1)/etc/vpnc/
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) ./files/vpnc.upgrade $(1)/lib/upgrade/keep.d/vpnc
endef

$(eval $(call BuildPackage,vpnc))
