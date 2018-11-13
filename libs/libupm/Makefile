#
# Copyright (C) 2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libupm
PKG_VERSION:=1.7.1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/intel-iot-devkit/upm/tar.gz/v$(PKG_VERSION)?
PKG_HASH:=b253742b01146f4b86e20714aa24e75ca1e9d46629eab9aa8db070ce94cf3619
PKG_BUILD_DIR:=$(BUILD_DIR)/upm-$(PKG_VERSION)

PKG_MAINTAINER:=John Crispin <blogic@openwrt.org>
PKG_LICENSE:=LGPL-2.1

CMAKE_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

UPM_MODULES:= \
	a110x abp ad8232 adafruitms1438 adafruitss adc121c021 adis16448 ads1x15 adxl335 adxl345 adxrs610 am2315 apa102 apds9002 apds9930 \
	at42qt1070 bh1749 bh1750 bh1792 biss0001 bma220 bma250e bmg160 bmi160 bmm150 bmp280 bmpx8x bmx055 bno055 button buzzer cjq4435 \
	collision cwlsxxa dfrec dfrorp dfrph ds1307 ds1808lc ds18b20 ds2413 ecezo ecs1030 ehr eldriver electromagnet emg enc03r flex gas \
	gp2y0a gprs grovecollision groveehr groveeldriver groveelectromagnet groveemg grovegprs grovegsr grovelinefinder grovemd \
	grovemoisture groveo2 grovescam grove grovespeaker groveultrasonic grovevdiv grovewater grovewfs gsr guvas12d h3lis331dl hcsr04 \
	hdc1000 hdxxvxta hka5 hlg150h hm11 hmc5883l hmtrp hp20x ht9170 htu21d hx711 ili9341 ims ina132 interfaces isd1820 itg3200 \
	jhd1313m1 joystick12 kx122 kxcjk1013 kxtj3 l298 l3gd20 lcdks lcd lcm1602 ldt0028 led lidarlitev3 light linefinder lis2ds12 \
	lis3dh lm35 lol loudness lp8860 lpd8806 lsm303agr lsm303dlh lsm303d lsm6ds3h lsm6dsl lsm9ds0 m24lr64e mag3110 max30100 max31723 \
	max31855 max44000 max44009 max5487 maxds3231m maxsonarez mb704x mcp2515 mcp9808 md mg811 mhz16 mic micsv89 mlx90614 mma7361 \
	mma7455 mma7660 mma8x5x mmc35240 moisture mpl3115a2 mpr121 mpu9150 mq303a my9221 nlgpio16 nmea_gps nrf24l01 nrf8001 nunchuck \
	o2 otp538u p9813 pca9685 pn532 ppd42ns pulsensor relay rf22 rfr359f rgbringcoder rhusb rn2903 rotaryencoder rotary rpr220 rsc \
	scam sensortemplate servo sht1x si1132 si114x si7005 slide sm130 smartdrive speaker ssd1351 st7735 stepmotor sx1276 sx6119 t6713 \
	ta12200 tca9548a tcs3414cs tcs37727 teams temperature tex00 th02 tm1637 tmp006 tsl2561 ttp223 uartat uln200xa ultrasonic urm37 \
	utilities vcap vdiv veml6070 waterlevel water wfs wheelencoder wt5001 xbee yg1006 zfm20

CMAKE_OPTIONS=-DBUILDARCH=$(CONFIG_ARCH) \
	-DNODE_EXECUTABLE=$(STAGING_DIR_HOSTPKG)/bin/node \
	-DPython_ADDITIONAL_VERSIONS=2.7

define Package/libupm/Default
  SECTION:=libs
  CATEGORY:=Libraries
  DEPENDS:=+libmraa +librt
  SUBMENU:=IoT
endef

define Package/libupm
  $(call Package/libupm/Default)
  TITLE:=Intel IoT sensor library - Full
endef

define Package/libupm/install/Default
	$(INSTALL_DIR) $(1)/usr/lib/{node/,python2.7/site-packages/upm}; \
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libupm-$(2).so* $(1)/usr/lib/; \
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/node_modules/jsupm_$(2) $(1)/usr/lib/node/; \
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/python2.7/site-packages/upm/_pyupm_$(2).so \
		$(1)/usr/lib/python2.7/site-packages/upm ;
endef

define Package/libupm/install
	$(foreach module, $(UPM_MODULES),	\
  		$(call Package/libupm/install/Default,$(1),$(module)))
endef

define UpmPackage
define Package/libupm-$(1)
  $(call Package/libupm/Default)
  TITLE:=Intel IoT sensor library - $(1)
endef

define Package/libupm-$(1)/install
  	$(call Package/libupm/install/Default,$$(1),$(1))
endef
endef

$(eval $(call BuildPackage,libupm))
$(foreach package, $(UPM_MODULES),			\
	$(eval $(call UpmPackage,$(package)))		\
	$(eval $(call BuildPackage,libupm-$(package)))	\
)
