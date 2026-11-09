import { DEBUG_API_URL } from "../../shared/core/api-url";

export type Flavor = "prod" | "debug";

export type FlavorIdentity = {
  flavor: Flavor;
  productName: string;
  appUserModelId: string;
  userDataName: string;
  devUserDataName: string;
  tunnelName: string;
  firewallGroup: string;
  firewallRulePrefix: string;
  firewallBackupFile: string;
  firewallSpecFile: string;
  autostartTask: string;
};

const IDENTITIES: Record<Flavor, FlavorIdentity> = {
  prod: {
    flavor: "prod",
    productName: "Mantel",
    appUserModelId: "net.mantel.desktop",
    userDataName: "Mantel",
    devUserDataName: "Mantel-Dev",
    tunnelName: "mantel",
    firewallGroup: "Mantel Kill Switch",
    firewallRulePrefix: "Mantel-KS-",
    firewallBackupFile: "firewall-backup.json",
    firewallSpecFile: "firewall-rules.json",
    autostartTask: "Mantel Autostart",
  },
  debug: {
    flavor: "debug",
    productName: "Mantel Debug",
    appUserModelId: "net.mantel.desktop.debug",
    userDataName: "Mantel Debug",
    devUserDataName: "Mantel-Debug-Dev",
    tunnelName: "mantel-debug",
    firewallGroup: "Mantel Debug Kill Switch",
    firewallRulePrefix: "MantelDebug-KS-",
    firewallBackupFile: "firewall-backup-debug.json",
    firewallSpecFile: "firewall-rules-debug.json",
    autostartTask: "Mantel Debug Autostart",
  },
};

export function identityOf(flavor: Flavor): FlavorIdentity {
  return IDENTITIES[flavor];
}

export const FLAVOR: Flavor = import.meta.env.MANTEL_FLAVOR === "debug" ? "debug" : "prod";
export const IS_DEBUG = import.meta.env.MANTEL_FLAVOR === "debug";
export const IDENTITY: FlavorIdentity = IDENTITIES[FLAVOR];
export const BUILD_TIME: string | null = import.meta.env.MANTEL_BUILD_TIME ?? null;

export const API_BASE_URL: string = import.meta.env.MANTEL_API_URL || DEBUG_API_URL.desktop;
