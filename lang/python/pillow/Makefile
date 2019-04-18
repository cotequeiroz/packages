#
# Copyright © 1997-2011 by Secret Labs AB
# Copyright © 1995-2011 by Fredrik Lundh
# Copyright © 2016 by Alex Clark and contributors
#

include $(TOPDIR)/rules.mk

PKG_NAME:=pillow
PKG_VERSION:=6.0.0
PKG_RELEASE:=1

PKG_SOURCE:=Pillow-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://files.pythonhosted.org/packages/source/P/Pillow
PKG_HASH:=809c0a2ce9032cbcd7b5313f71af4bdc5c8c771cb86eb7559afd954cab82ebb5

PKG_BUILD_DIR:=$(BUILD_DIR)/$(BUILD_VARIANT)-Pillow-$(PKG_VERSION)

PKG_MAINTAINER:=Alexandru Ardelean <ardeleanalex@gmail.com>
PKG_LICENSE:=HPND
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk
include ../python-package.mk
include ../python3-package.mk

PKG_UNPACK:=$(HOST_TAR) -C $(PKG_BUILD_DIR) --strip-components=1 -xzf $(DL_DIR)/$(PKG_SOURCE)

define Package/python-pillow/Default
  SUBMENU:=Python
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=The friendly PIL fork
  URL:=https://python-pillow.org/
  DEPENDS:=+libjpeg +libtiff +zlib
endef

define Package/python-pillow
$(call Package/python-pillow/Default)
  DEPENDS+=+PACKAGE_python-pillow:python
  VARIANT:=python
endef

define Package/python-pillow/description
  The friendly PIL fork
endef

define Package/python3-pillow
$(call Package/python-pillow/Default)
  DEPENDS+=+PACKAGE_python3-pillow:python3
  VARIANT:=python3
endef

define Package/python3-pillow/description
$(call Package/python-pillow/description)
.
(Variant for Python3)
endef

$(eval $(call PyPackage,python-pillow))
$(eval $(call BuildPackage,python-pillow))
$(eval $(call BuildPackage,python-pillow-src))

$(eval $(call Py3Package,python3-pillow))
$(eval $(call BuildPackage,python3-pillow))
$(eval $(call BuildPackage,python3-pillow-src))
