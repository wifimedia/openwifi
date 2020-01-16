#
# Copyright (C) 2006-2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gwls
PKG_VERSION:=1.6.01
PKG_RELEASE:=1
PKG_MAINTAINER:=Dungtd <dungtd8x@gmail.com>
PKG_LICENSE:=GPLv2

include $(INCLUDE_DIR)/package.mk

define Package/gwls
  SUBMENU:=Wifimedia
  SECTION:=dev
  CATEGORY:=Advance
  TITLE:=Gateway License 
  URL:=http://wifimedia.vn
  MENU:=1
  PKGARCH:=all
  MAINTAINER:=DungTD <dungtd8x@gmail.com>
endef

define Package/gwls/description

endef

define Build/Compile
endef

define Package/gwls/install
	#$(INSTALL_DIR) $(1)
	#$(CP) ./files/* $(1)
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/opt
	$(INSTALL_DIR) $(1)/etc/opt/license
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/usr/bin
	
	$(INSTALL_BIN) ./files/license_uci $(1)/etc/uci-defaults/license
	$(INSTALL_BIN) ./files/license.sh $(1)/usr/bin/license.sh
	#$(INSTALL_BIN) ./files/initd_wifimedia_check $(1)/etc/init.d/wifimedia_check
endef

define Package/gwls/postinst
#!/bin/sh
# check if we are on real system
if [ -z "${IPKG_INSTROOT}" ]; then
	echo "Removing rc.d symlink for upwifi"
	/etc/init.d/upwifi disable
fi
exit 0
endef

$(eval $(call BuildPackage,gwls))