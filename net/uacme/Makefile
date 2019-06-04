#
# Copyright (C) 2019 Lucian Cristian <lucian.cristian@gmail.com>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=uacme
PKG_VERSION:=1.0.15
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/ndilieto/uacme/tar.gz/upstream/$(PKG_VERSION)?
PKG_HASH:=b22e001928dd80249d7245b0cb61281ed487f8f1bd337b1264a754acf347561d

PKG_MAINTAINER:=Lucian Cristian <lucian.cristian@gmail.com>
PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILES:=COPYING

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-upstream-$(PKG_VERSION)
PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1

PKG_CONFIG_DEPENDS:= \
  CONFIG_LIBCURL_GNUTLS \
  CONFIG_LIBCURL_MBEDTLS \
  CONFIG_LIBCURL_OPENSSL \
  CONFIG_LIBCURL_WOLFSSL

include $(INCLUDE_DIR)/package.mk

define Package/uacme
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libcurl +LIBCURL_WOLFSSL:libmbedtls
  TITLE:=lightweight client for ACMEv2
  URL:=https://github.com/ndilieto/uacme
endef

define Package/uacme/Default/description
  lightweight client for the RFC8555 ACMEv2 protocol, written in plain C code
  with minimal dependencies (libcurl and one of GnuTLS, OpenSSL or mbedTLS).
  The ACMEv2 protocol allows a Certificate Authority (https://letsencrypt.org
  is a popular one) and an applicant to automate the process of verification
  and certificate issuance. The protocol also provides facilities for other
  certificate management functions, such as certificate revocation.
endef

TARGET_LDFLAGS += -Wl,--gc-sections,--as-needed

CONFIGURE_ARGS+= \
	--disable-maintainer-mode \
	--disable-docs \
	$(if $(CONFIG_LIBCURL_GNUTLS),--with-gnutls --without-mbedtls --without-openssl,) \
	$(if $(CONFIG_LIBCURL_MBEDTLS),--without-gnutls --with-mbedtls --without-openssl,) \
	$(if $(CONFIG_LIBCURL_OPENSSL),--without-gnutls --without-mbedtls --with-openssl,) \
	$(if $(CONFIG_LIBCURL_WOLFSSL),--without-gnutls --with-mbedtls --without-openssl,)

define Package/uacme/install
	$(INSTALL_DIR) \
	 $(1)/usr/bin \
	 $(1)/usr/share/uacme

	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/uacme $(1)/usr/bin/uacme
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/share/uacme/uacme.sh $(1)/usr/share/uacme/
endef

$(eval $(call BuildPackage,uacme))
