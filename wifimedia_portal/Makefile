#
# Copyright (C) 2006-2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wifimedia_portal
PKG_VERSION:=2.0
PKG_RELEASE:=1
PKG_MAINTAINER:=Dungtd <dungtd8x@gmail.com>
PKG_LICENSE:=GPLv2

include $(INCLUDE_DIR)/package.mk

define Package/wifimedia_portal
  SUBMENU:=Wifimedia
  SECTION:=dev
  CATEGORY:=Advance
  DEPENDS:=+nodogsplash
  TITLE:=Wireless LAN HotSpot controller 
  URL:=http://wifimedia.vn
  MENU:=1
  PKGARCH:=all
  MAINTAINER:=DungTD <dungtd8x@gmail.com>
endef

define Package/wifimedia_portal/description
	Wifimedia offer it supports Wireless
endef

define Build/Compile
endef

define Package/wifimedia_portal/install
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_DIR) $(1)/sbin/wifimedia
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller/wifimedia
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi/wifimedia_module
	$(INSTALL_BIN) ./files/uci_portal $(1)/etc/uci-defaults/uci_portal
	$(INSTALL_BIN) ./files/captive_portal.sh $(1)/sbin/wifimedia/captive_portal.sh
	$(INSTALL_DATA) ./files/wifimedia_portal.lua $(1)/usr/lib/lua/luci/controller/wifimedia/wifimedia_portal.lua
	$(INSTALL_DATA) ./files/portal_model.lua $(1)/usr/lib/lua/luci/model/cbi/wifimedia_module/wifimedia_portal.lua
	$(INSTALL_BIN) ./files/nodogsplash_int $(1)/etc/init.d/nodogsplash
endef
$(eval $(call BuildPackage,wifimedia_portal))