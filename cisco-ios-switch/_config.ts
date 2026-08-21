import type { AccessPortRange, CiscoIosGlobalArgs, Vlan } from "./_ssh.ts";

/**
 * Pure IOS config-line generators and output sanitizers for the
 * `@dougschaefer/cisco-ios-switch` model. These have no I/O and no Deno
 * dependencies, so they are unit-tested directly and shared by the model's
 * dry-run and live paths.
 */

/** Secure-access hardening lines asserted idempotently by `applyBaseline`. */
export function baselineLines(g: CiscoIosGlobalArgs): string[] {
  const lines: string[] = [];
  if (g.hostname) lines.push(`hostname ${g.hostname}`);
  if (g.domainName) lines.push(`ip domain-name ${g.domainName}`);
  lines.push(
    "service password-encryption",
    "no ip http server",
    "no ip http secure-server",
    "ip ssh version 2",
    "line console 0",
    " logging synchronous",
    " exec-timeout 15 0",
    " login local",
    "exit",
    "line vty 0 15",
    " exec-timeout 15 0",
    " logging synchronous",
    " login local",
    " transport input ssh",
    "exit",
  );
  return lines;
}

/** SNMPv2c lines from `globalArguments.snmp`. */
export function snmpLines(g: CiscoIosGlobalArgs): string[] {
  const s = g.snmp!;
  const lines: string[] = [];
  if (s.readOnly) lines.push(`snmp-server community ${s.readOnly} RO`);
  if (s.readWrite) lines.push(`snmp-server community ${s.readWrite} RW`);
  if (s.location) lines.push(`snmp-server location ${s.location}`);
  if (s.contact) lines.push(`snmp-server contact ${s.contact}`);
  if (s.trapHost && s.readOnly) {
    lines.push(`snmp-server host ${s.trapHost} version 2c ${s.readOnly}`);
    lines.push("snmp-server enable traps");
  }
  return lines;
}

/** Layer-3 / VLAN lines from `globalArguments.routing`. */
export function routingLines(g: CiscoIosGlobalArgs): string[] {
  const r = g.routing!;
  const lines: string[] = [];
  if (r.enabled) lines.push("ip routing");
  for (const v of r.vlans as Vlan[]) {
    lines.push(`vlan ${v.id}`, ` name ${v.name}`, "exit");
    if (v.sviIp && v.sviMask) {
      lines.push(
        `interface vlan ${v.id}`,
        ` description ${v.name} gateway`,
        ` ip address ${v.sviIp} ${v.sviMask}`,
        " no shutdown",
        "exit",
      );
    }
  }
  if (r.enabled && r.defaultRouteNextHop) {
    lines.push(`ip route 0.0.0.0 0.0.0.0 ${r.defaultRouteNextHop}`);
  }
  for (const p of r.accessPorts as AccessPortRange[]) {
    lines.push(`interface range ${p.range}`);
    if (p.description) lines.push(` description ${p.description}`);
    lines.push(
      " switchport mode access",
      ` switchport access vlan ${p.vlanId}`,
    );
    if (p.portfast) lines.push(" spanning-tree portfast");
    lines.push("exit");
  }
  return lines;
}

/** Parse hostname/model/IOS version/uptime out of `show version`. */
export function parseShowVersion(text: string): {
  hostname: string;
  model: string;
  iosVersion: string;
  uptime: string;
} {
  const uptimeMatch = text.match(/^(\S+)\s+uptime is\s+(.+)$/m);
  const versionMatch = text.match(/Version\s+([^\s,]+)/);
  const explicitModelMatch = text.match(/Model number\s*:\s*(\S+)/i);
  const bannerModelMatch = text.match(
    /\bcisco\s+(\S*(?:2960|C1000|C9)\S*)/i,
  );
  return {
    hostname: uptimeMatch?.[1]?.trim() ?? "",
    model: explicitModelMatch?.[1]?.trim() ??
      bannerModelMatch?.[1]?.trim() ?? "",
    iosVersion: versionMatch?.[1]?.trim() ?? "",
    uptime: uptimeMatch?.[2]?.trim() ?? "",
  };
}

/**
 * Parse `show mac address-table` into rows, normalizing each MAC to the
 * colon-separated uppercase form the inventory DB uses (`mac_address.mac_address`),
 * so a caller can join on it without re-normalizing.
 *
 * WHY THIS EXISTS: a MAC being LEARNED on a switch port is an out-of-band witness
 * that a device is powered and transmitting, obtained without touching the device.
 * That is the only signal that separates "the address we hold is stale" from "the
 * device is dead" -- two states that look identical from the address alone, and
 * which were confused in both directions on 2026-08-21 (a healthy iDRAC that had
 * moved VLAN was diagnosed as dead, and that diagnosis then propagated into an
 * extension's docs and a T1 workflow before the switch MAC table settled it).
 *
 * PARSED BY TOKEN SHAPE, NOT BY COLUMN POSITION. Each line is anchored on the
 * Cisco dotted-triple MAC and the remaining tokens are classified by what they
 * look like -- a numeric-or-"All" VLAN, a known entry type, and the ports. This
 * repo has already been bitten by positional parsing (`mstconfig`'s column order
 * is Default/Current/NextBoot, which is not the order anyone assumes), so column
 * order is deliberately not relied on here. Header, separator, and total lines
 * carry no dotted MAC and are skipped as a consequence of the anchor rather than
 * by pattern-matching their text, which also means a firmware release that
 * reworks the banner cannot break this.
 *
 * Entry TYPE is preserved rather than reduced to a boolean: only a DYNAMIC entry
 * proves current transmission. A STATIC entry is configuration, and the CPU
 * entries are the switch talking about itself -- treating either as a liveness
 * witness would manufacture evidence.
 */
export function parseMacAddressTable(text: string): Array<{
  vlan: string;
  mac: string;
  type: string;
  ports: string[];
}> {
  const DOTTED = /^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$/;
  const KNOWN_TYPES = new Set([
    "dynamic",
    "static",
    "sticky",
    "secure",
    "self",
    "igmp",
  ]);
  const rows: Array<
    { vlan: string; mac: string; type: string; ports: string[] }
  > = [];
  for (const line of text.split(/\r?\n/)) {
    const tokens = line.trim().split(/\s+/).filter((t) => t.length > 0);
    const macIdx = tokens.findIndex((t) => DOTTED.test(t));
    if (macIdx === -1) continue;
    const mac = normalizeCiscoMac(tokens[macIdx]);
    const rest = tokens.filter((_, i) => i !== macIdx);
    let vlan = "";
    let type = "";
    const ports: string[] = [];
    for (const t of rest) {
      if (!vlan && (/^\d+$/.test(t) || t.toLowerCase() === "all")) {
        vlan = t;
      } else if (!type && KNOWN_TYPES.has(t.toLowerCase())) {
        type = t.toUpperCase();
      } else {
        ports.push(t);
      }
    }
    rows.push({ vlan, mac, type, ports });
  }
  return rows;
}

/**
 * `6c3c.8c99.550b` -> `6C:3C:8C:99:55:0B`.
 *
 * Cisco prints dotted-triple; the inventory DB stores colon-separated uppercase.
 * Normalizing at the parse boundary means exactly one representation leaves this
 * module, so a caller cannot accidentally compare the two forms and get a false
 * "not found" -- the same class of silent miss as the `port.mac`/`has_mac` split.
 */
export function normalizeCiscoMac(dotted: string): string {
  const hex = dotted.replace(/\./g, "").toUpperCase();
  return hex.match(/.{2}/g)?.join(":") ?? dotted.toUpperCase();
}

/** Replace community/secret/password/key values on a single config line. */
export function redactLine(line: string): string {
  return line
    .replace(/(snmp-server community\s+)(\S+)/i, "$1<redacted>")
    .replace(
      /(snmp-server host\s+\S+\s+(?:(?:traps|informs)\s+)?version\s+\S+\s+)(\S+)/i,
      "$1<redacted>",
    )
    .replace(
      /(snmp-server host\s+\S+\s+(?:traps|informs)\s+)(?!version\b)(\S+)/i,
      "$1<redacted>",
    )
    .replace(
      /(snmp-server host\s+\S+\s+)(?!(?:traps|informs|version)\b)(\S+)/i,
      "$1<redacted>",
    )
    // secret/password values can be "type hash" (e.g. "5 $1$..") — redact to EOL.
    .replace(/(\bsecret\s+)(.+)$/i, "$1<redacted>")
    .replace(/(\bpassword\s+)(.+)$/i, "$1<redacted>")
    .replace(
      /(\bsnmp-server\s+user\s+\S+\s+\S+\s+auth\s+\S+\s+)(\S+)/i,
      "$1<redacted>",
    )
    .replace(
      /(\bsnmp-server\s+user\b.*?\spriv\s+\S+(?:\s+\d+)?\s+)(\S+)/i,
      "$1<redacted>",
    )
    .replace(
      /(\b(?:radius|tacacs)-server(?:\s+host\s+\S+)?\s+key\s+(?:\d+\s+)?)(\S+)/i,
      "$1<redacted>",
    )
    .replace(
      /(\bserver-private\s+\S+.*?\skey\s+(?:\d+\s+)?)(\S+)/i,
      "$1<redacted>",
    )
    .replace(
      /(\bip\s+ospf\s+message-digest-key\s+\d+\s+\S+\s+(?:\d+\s+)?)(\S+)/i,
      "$1<redacted>",
    )
    .replace(
      /(\bip\s+ospf\s+authentication-key\s+(?:\d+\s+)?)(\S+)/i,
      "$1<redacted>",
    )
    .replace(
      /(\bntp\s+authentication-key\s+\d+\s+\S+\s+)(\S+)/i,
      "$1<redacted>",
    )
    .replace(
      /(\bcrypto\s+isakmp\s+key\s+(?:\d+\s+)?)(\S+)/i,
      "$1<redacted>",
    )
    .replace(
      /(\bpre-shared-key\b.*?\bkey\s+(?:\d+\s+)?)(\S+)/i,
      "$1<redacted>",
    )
    .replace(/(\bkey-string\s+(?:\d+\s+)?)(\S+)/i, "$1<redacted>")
    .replace(/(\bkey\s+)(\d.*)$/i, "$1<redacted>");
}

/** Strip secret-bearing lines from a running-config before storage. */
export function redactConfig(config: string): string {
  return config
    .split(/\r?\n/)
    .map((l) =>
      /^\s*(snmp-server\s+(?:community|host|user)|enable\s+(?:secret|password)|username\s+.*\s+(?:secret|password)|(?:radius|tacacs)-server\b.*\bkey|server-private\s+\S+.*\bkey|ip\s+ospf\s+(?:authentication-key|message-digest-key)|ntp\s+authentication-key|crypto\s+isakmp\s+key|pre-shared-key\b.*\bkey|neighbor\s+\S+\s+password|.*\bkey-string\s+(?:\d+\s+)?\S+|.*\bpassword\b|key\s+\d)/i
          .test(l)
        ? redactLine(l)
        : l
    )
    .join("\n");
}

const SENSITIVE_JSON_KEY_RE =
  /(?:password|passphrase|secret|token|community|auth(?:entication)?|authkey|priv(?:acy)?|privkey|privacykey|privatekey|encryptionkey|keystring|apikey)$|^key$/i;

function redactJsonValue(value: unknown, key = ""): unknown {
  if (SENSITIVE_JSON_KEY_RE.test(key)) return "<redacted>";
  if (Array.isArray(value)) {
    return value.map((item) => redactJsonValue(item));
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, childValue]) => [
        childKey,
        redactJsonValue(childValue, childKey.replace(/[-_]/g, "")),
      ]),
    );
  }
  return typeof value === "string" ? redactConfig(value) : value;
}

/** Redact text or JSON command output without corrupting structured JSON. */
export function redactCommandOutput(output: string): string {
  try {
    return JSON.stringify(redactJsonValue(JSON.parse(output)));
  } catch {
    return redactConfig(output);
  }
}
