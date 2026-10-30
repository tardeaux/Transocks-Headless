include $(TOPDIR)/rules.mk

PKG_NAME:=transocks-headless
PKG_VERSION:=0.1.0
PKG_RELEASE:=3

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Transocks Headless maintainers
PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/transocks-headless/transocks-headless
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd/transocks-headless
GO_PKG_LDFLAGS_X:=main.version=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/transocks-headless
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=Headless Transocks client and adaptive host controller
  URL:=https://www.transocks.com/
  DEPENDS:=$(GO_ARCH_DEPENDS) +sing-box +ca-bundle +firewall4 +ip-full +kmod-tun
endef

define Package/transocks-headless/description
 Clean-room OpenWrt controller for Transocks account login, endpoint discovery,
 adaptive Shadowsocks/Trojan selection, sing-box supervision, and failover.
endef

define Package/transocks-headless/config
config TRANSOCKS_HEADLESS_REQUIRE_CLASH_API
	bool
	depends on PACKAGE_transocks-headless
	default y
	select SINGBOX_WITH_CLASH_API if PACKAGE_sing-box
endef

define Package/transocks-headless/conffiles
/etc/config/transocks
/etc/transocks/credentials.json
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/. $(PKG_BUILD_DIR)/
	$(CP) ./LICENSE $(PKG_BUILD_DIR)/
endef

define Package/transocks-headless/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/transocks-headless $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/transocks.config $(1)/etc/config/transocks
	$(INSTALL_DIR) $(1)/etc/transocks
	$(INSTALL_CONF) ./files/credentials.json $(1)/etc/transocks/credentials.json
	chmod 0600 $(1)/etc/transocks/credentials.json
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/transocks.init $(1)/etc/init.d/transocks
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/99-transocks-device-id $(1)/etc/uci-defaults/
endef

$(eval $(call GoBinPackage,transocks-headless))
$(eval $(call BuildPackage,transocks-headless))
