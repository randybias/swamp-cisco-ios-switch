import { z } from "npm:zod@4.3.6";

/**
 * Shared schema and SSH session driver for the
 * `@dougschaefer/cisco-ios-switch` model.
 *
 * Cisco IOS SSH servers expose an interactive EXEC shell, not a true
 * SSH "exec" channel, so configuration is driven the way a human would
 * at the VTY: disable the `--More--` pager, optionally enter privileged
 * mode, then feed commands and read the resulting transcript.
 *
 * The transport shells out to the system `ssh` client rather than
 * bundling a JS SSH library — swamp bundles extensions with `deno
 * bundle`, which statically resolves the optional native `.node`
 * addons inside `ssh2`/`cpu-features` and fails. Shelling out (the same
 * pattern the opnsense model uses for `curl`) keeps the bundle clean
 * and depends only on stock OpenSSH (>= 8.4 for SSH_ASKPASS_REQUIRE).
 * The login password is handed to `ssh` through a 0600 askpass helper,
 * never on the command line.
 *
 * Connection facts and the per-switch baseline (SNMP communities,
 * routing/VLANs) live in `globalArguments` so a model definition is one
 * switch and secrets resolve from vault, e.g.:
 *   password:        ${{ vault.get(your-vault, switch-admin) }}
 *   snmp.readWrite:  ${{ vault.get(your-vault, switch-snmp-rw) }}
 *
 * Old 2960 IOS images negotiate only legacy SSH algorithms
 * (diffie-hellman-group1/14-sha1, ssh-rsa host keys, aes-cbc), which
 * modern clients disable by default — `legacyAlgorithms` (on by default)
 * appends them to the offer so the handshake succeeds.
 */

/** A VLAN to create, optionally with a routed SVI gateway address. */
const VlanSchema = z.object({
  id: z.number().int().min(1).max(4094).describe("VLAN ID (1-4094)"),
  name: z.string().describe("VLAN name, e.g. USER_DATA"),
  sviIp: z.string().optional().describe(
    "SVI gateway IP for this VLAN. Omit for an L2-only VLAN (no routed interface).",
  ),
  sviMask: z.string().optional().describe(
    "SVI subnet mask, e.g. 255.255.255.0. Required when sviIp is set.",
  ),
});

/** An access-port range and the VLAN its members are placed in. */
const AccessPortRangeSchema = z.object({
  range: z.string().describe(
    "Interface range as IOS expects it, e.g. 'fastEthernet 0/1 - 12' or 'gigabitEthernet 1/0/1 - 12'.",
  ),
  vlanId: z.number().int().describe("Access VLAN assigned to the range"),
  description: z.string().default("").describe("Port description"),
  portfast: z.boolean().default(true).describe(
    "Enable spanning-tree portfast on the range (edge ports)",
  ),
});

/** SNMPv2c communities and identity. Community strings are vault-resolved secrets. */
const SnmpSchema = z.object({
  readOnly: z.string().meta({ sensitive: true }).optional().describe(
    "SNMPv2c read-only community. Use: ${{ vault.get(your-vault, <switch>-snmp-ro) }}",
  ),
  readWrite: z.string().meta({ sensitive: true }).optional().describe(
    "SNMPv2c read-write community. Use: ${{ vault.get(your-vault, <switch>-snmp-rw) }}",
  ),
  location: z.string().optional().describe("snmp-server location string"),
  contact: z.string().optional().describe("snmp-server contact string"),
  trapHost: z.string().optional().describe(
    "Trap destination IP (manager/monitor). When set, traps are enabled to this host using the read-only community.",
  ),
});

/** Layer-3 intent: enable routing, create routed VLANs/SVIs, a default route, and access-port assignments. */
const RoutingSchema = z.object({
  enabled: z.boolean().default(false).describe(
    "Run 'ip routing'. Many 2960 variants do not support this — confirm the model/IOS feature set first.",
  ),
  defaultRouteNextHop: z.string().optional().describe(
    "Next-hop for 'ip route 0.0.0.0 0.0.0.0 <next-hop>' (used when routing is enabled).",
  ),
  vlans: z.array(VlanSchema).default([]).describe(
    "VLANs to create (with optional SVIs)",
  ),
  accessPorts: z.array(AccessPortRangeSchema).default([]).describe(
    "Access-port ranges to assign to VLANs",
  ),
});

/**
 * Global arguments for a managed Cisco IOS switch: SSH connection
 * facts plus the per-switch baseline this model asserts over SSH.
 */
export const CiscoIosGlobalArgsSchema = z.object({
  host: z.string().describe("Management IP or hostname of the switch"),
  port: z.number().int().default(22).describe("SSH port"),
  username: z.string().describe("SSH username (a privilege-15 local user)"),
  password: z.string().meta({ sensitive: true }).describe(
    "SSH password. Use: ${{ vault.get(your-vault, <switch>-admin) }}",
  ),
  enableSecret: z.string().meta({ sensitive: true }).optional().describe(
    "Enable secret. Set ONLY if the login does not land in privileged EXEC; sends 'enable' + this secret. Leave unset for a privilege-15 login.",
  ),
  hostname: z.string().optional().describe(
    "Hostname asserted by applyBaseline (does not rename the SSH target).",
  ),
  domainName: z.string().optional().describe(
    "IP domain-name asserted by applyBaseline.",
  ),
  legacyAlgorithms: z.boolean().default(true).describe(
    "Append legacy SSH kex/cipher/host-key algorithms to the offer for old IOS images.",
  ),
  commandTimeoutMs: z.number().int().default(20000).describe(
    "SSH connect timeout (seconds, rounded up) and the per-session output read budget, in milliseconds.",
  ),
  snmp: SnmpSchema.optional().describe("SNMPv2c configuration (pushSnmp)"),
  routing: RoutingSchema.optional().describe(
    "Layer-3 / VLAN configuration (pushRouting)",
  ),
});

export type CiscoIosGlobalArgs = z.infer<typeof CiscoIosGlobalArgsSchema>;
export type Vlan = z.infer<typeof VlanSchema>;
export type AccessPortRange = z.infer<typeof AccessPortRangeSchema>;

/** A unit of work for one SSH session. */
export interface IosPlan {
  /** EXEC/show commands run for their output (not inside config mode). */
  execCommands?: string[];
  /** Lines run inside `configure terminal` … `end`. */
  configLines?: string[];
  /** Run `write memory` after applying configLines. */
  save?: boolean;
}

/** Captured output of a single EXEC command. */
export interface ExecOutput {
  command: string;
  output: string;
}

/** Result of a single SSH session. */
export interface IosResult {
  /** Full session transcript (echoes, output, prompts). */
  transcript: string;
  /** Per-command output for the EXEC commands in the plan. */
  execOutputs: ExecOutput[];
}

/** IOS rejection lines: '% Invalid input', '% Incomplete command', etc. (not syslog like %SYS-5-…). */
const IOS_ERROR_RE =
  /^%\s+(invalid|incomplete|ambiguous|unrecognized|unknown|bad|cannot|error|not a valid|duplicate|overlaps)/i;

/** Build the `-o` algorithm flags that append legacy algorithms to the offer. */
function legacyAlgoFlags(): string[] {
  return [
    "-o",
    "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1",
    // ssh-dss (DSA host keys) was removed entirely from modern OpenSSH — including
    // it makes the whole HostKeyAlgorithms list error ("Bad key types"). Old 2960
    // images present an RSA host key, so +ssh-rsa is what actually matters.
    "-o",
    "HostKeyAlgorithms=+ssh-rsa",
    "-o",
    "Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc",
    "-o",
    "MACs=+hmac-sha1,hmac-md5",
  ];
}

/** Lines fed to the IOS VTY for a plan, in order. */
function buildScript(args: CiscoIosGlobalArgs, plan: IosPlan): string[] {
  const lines: string[] = [];
  if (args.enableSecret) lines.push("enable", args.enableSecret);
  lines.push("terminal length 0", "terminal width 0");
  for (const c of plan.execCommands ?? []) lines.push(c);
  if (plan.configLines && plan.configLines.length > 0) {
    lines.push("configure terminal", ...plan.configLines, "end");
    if (plan.save) lines.push("write memory");
  }
  lines.push("exit");
  return lines;
}

/**
 * Open one SSH session to the switch and run a plan: optional EXEC
 * commands (captured) and/or a `configure terminal` block (optionally
 * saved). Throws on connect/auth failure, session timeout, or any IOS
 * rejection line in the output. Returns the transcript and per-command
 * EXEC output.
 */
export async function runIosSession(
  args: CiscoIosGlobalArgs,
  plan: IosPlan,
): Promise<IosResult> {
  const sent = buildScript(args, plan);
  const script = sent.join("\n") + "\n";

  // Hand the password to ssh via a private askpass helper — never argv.
  const tmp = await Deno.makeTempDir({ prefix: "ios-ssh-" });
  const pwFile = `${tmp}/pw`;
  const askpass = `${tmp}/askpass.sh`;
  try {
    await Deno.writeTextFile(pwFile, args.password);
    await Deno.chmod(pwFile, 0o600);
    await Deno.writeTextFile(askpass, `#!/bin/sh\ncat ${pwFile}\n`);
    await Deno.chmod(askpass, 0o700);

    const connectSecs = Math.max(5, Math.ceil(args.commandTimeoutMs / 1000));
    const sshArgs = [
      "-tt",
      "-p",
      String(args.port),
      // Host-key verification is intentionally disabled: these switches are
      // managed over a trusted L2 management network and are commonly
      // re-imaged (post-bootstrap), so there is no stable known_hosts entry to
      // pin. This trades MITM protection for operability — only run this model
      // against switches reachable over a trusted management path.
      "-o",
      "StrictHostKeyChecking=no",
      "-o",
      "UserKnownHostsFile=/dev/null",
      "-o",
      "GlobalKnownHostsFile=/dev/null",
      "-o",
      "LogLevel=ERROR",
      "-o",
      `ConnectTimeout=${connectSecs}`,
      "-o",
      "PubkeyAuthentication=no",
      "-o",
      "PreferredAuthentications=password,keyboard-interactive",
      "-o",
      "NumberOfPasswordPrompts=1",
    ];
    if (args.legacyAlgorithms) sshArgs.push(...legacyAlgoFlags());
    sshArgs.push(`${args.username}@${args.host}`);

    // Overall budget: connect + a per-line allowance, floor of 30s.
    const overallMs = Math.max(30000, connectSecs * 1000 + sent.length * 1500);
    const ac = new AbortController();
    const killer = setTimeout(() => ac.abort(), overallMs);

    const cmd = new Deno.Command("ssh", {
      args: sshArgs,
      env: {
        SSH_ASKPASS: askpass,
        SSH_ASKPASS_REQUIRE: "force",
        DISPLAY: ":0",
      },
      stdin: "piped",
      stdout: "piped",
      stderr: "piped",
      signal: ac.signal,
    });

    let output: Deno.CommandOutput;
    try {
      const child = cmd.spawn();
      const writer = child.stdin.getWriter();
      await writer.write(new TextEncoder().encode(script));
      // Do NOT close stdin before reading the reply. With a forced PTY
      // (`ssh -tt`), closing stdin sends EOF straight into the interactive IOS
      // VTY, which tears the session down before it finishes running the
      // script — only the first line's echo makes it back, so every command's
      // captured output comes back empty. The script already ends with `exit`,
      // which the device uses to close the session cleanly; `child.output()`
      // then returns the full transcript. The AbortController above is the
      // backstop if a device never closes the session. Release the writer
      // afterward (the pipe is already gone once the remote exits).
      output = await child.output();
      await writer.close().catch(() => {});
    } catch (e) {
      if (ac.signal.aborted) {
        throw new Error(
          `SSH session to ${args.host} exceeded ${overallMs} ms and was aborted`,
        );
      }
      throw e instanceof Error ? e : new Error(String(e));
    } finally {
      clearTimeout(killer);
    }

    const transcript = new TextDecoder().decode(output.stdout).replace(
      /\r/g,
      "",
    );
    const stderr = new TextDecoder().decode(output.stderr).trim();

    if (transcript.trim() === "") {
      const why = classifySshError(stderr) ?? stderr ?? "no output";
      throw new Error(`SSH to ${args.host} produced no session: ${why}`);
    }
    const authErr = classifySshError(stderr);
    if (authErr) throw new Error(`SSH to ${args.host} failed: ${authErr}`);

    return {
      transcript,
      execOutputs: sliceExecOutputs(transcript, sent, plan.execCommands ?? []),
    };
  } finally {
    await Deno.remove(tmp, { recursive: true }).catch(() => {});
  }
}

/** Map common ssh stderr signatures to a clear cause, or null if none seen. */
function classifySshError(stderr: string): string | null {
  if (/permission denied/i.test(stderr)) {
    return "authentication failed (permission denied)";
  }
  if (/connection refused/i.test(stderr)) return "connection refused";
  if (/connection timed out|operation timed out/i.test(stderr)) {
    return "connection timed out";
  }
  if (/no matching (key exchange|host key|cipher|mac)/i.test(stderr)) {
    return `algorithm negotiation failed (${stderr.split("\n")[0]})`;
  }
  if (/could not resolve hostname/i.test(stderr)) {
    return "host could not be resolved";
  }
  return null;
}

/** Slice per-command output out of the transcript by locating each sent line's echo. */
function sliceExecOutputs(
  transcript: string,
  sent: string[],
  execCommands: string[],
): ExecOutput[] {
  const positions: ({ start: number; end: number } | null)[] = [];
  let cursor = 0;
  for (const line of sent) {
    const idx = transcript.indexOf(line, cursor);
    if (idx === -1) {
      positions.push(null);
      continue;
    }
    positions.push({ start: idx, end: idx + line.length });
    cursor = idx + line.length;
  }
  const result: ExecOutput[] = [];
  for (let i = 0; i < sent.length; i++) {
    if (!execCommands.includes(sent[i])) continue;
    const pos = positions[i];
    if (!pos) {
      result.push({ command: sent[i], output: "" });
      continue;
    }
    let nextStart = transcript.length;
    for (let j = i + 1; j < sent.length; j++) {
      if (positions[j]) {
        nextStart = positions[j]!.start;
        break;
      }
    }
    result.push({
      command: sent[i],
      output: cleanOutput(transcript.slice(pos.end, nextStart)),
    });
  }
  return result;
}

/** Trim a leading newline and a trailing prompt line from a captured output slice. */
function cleanOutput(raw: string): string {
  const lines = raw.split("\n");
  while (lines.length > 0 && lines[0].trim() === "") lines.shift();
  if (lines.length > 0 && /[#>]\s*$/.test(lines[lines.length - 1])) lines.pop();
  return lines.join("\n").trim();
}

/** Return the first IOS rejection line in `output`, or null. */
export function findIosError(output: string): string | null {
  for (const raw of output.split(/\r?\n/)) {
    const line = raw.trim();
    if (IOS_ERROR_RE.test(line)) return line;
  }
  return null;
}
