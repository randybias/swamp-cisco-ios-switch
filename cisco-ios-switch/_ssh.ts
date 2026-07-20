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
 * Some old 2960 IOS images negotiate only legacy SSH algorithms
 * (diffie-hellman-group1/14-sha1, ssh-rsa host keys, aes-cbc), which
 * modern clients disable by default — `legacyAlgorithms` explicitly appends
 * them to the offer when compatibility is required.
 */

const HostSchema = z.string().min(1).max(253).regex(
  /^(?!-)[A-Za-z0-9._:[\]%-]+$/,
  "Host must be a hostname or IP address without whitespace, path, or option syntax",
);

const CiscoHostnameSchema = z.string().min(1).max(63).regex(
  /^(?!-)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/,
  "Cisco hostname must contain only letters, digits, and interior hyphens",
);

const DomainNameSchema = z.string().min(1).max(253).regex(
  /^(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/,
  "Domain name must be a dot-separated DNS name",
);

const Ipv4Schema = z.string().refine((value) => {
  const parts = value.split(".");
  return parts.length === 4 &&
    parts.every((part) =>
      /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255
    );
}, "Must be an IPv4 address");

const NetmaskSchema = Ipv4Schema.refine((value) => {
  const bits = value.split(".").map((part) =>
    Number(part).toString(2).padStart(8, "0")
  ).join("");
  return /^1+0*$/.test(bits);
}, "Must be a contiguous IPv4 subnet mask");

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const code = character.codePointAt(0)!;
    return code < 32 || code === 127;
  });
}

const SingleLineTextSchema = z.string().min(1).max(200).refine(
  (value) => !containsControlCharacter(value),
  "Value must be a single line without control characters",
);

const VaultValueSchema = z.string().min(1).meta({ sensitive: true }).refine(
  (value) => !containsControlCharacter(value),
  "Secret must not be empty or contain control characters",
).meta({ sensitive: true });

const SnmpCommunitySchema = VaultValueSchema.regex(
  /^\S+$/,
  "Community must not contain whitespace",
).meta({ sensitive: true });

/** A VLAN to create, optionally with a routed SVI gateway address. */
const VlanSchema = z.object({
  id: z.number().int().min(1).max(4094).describe("VLAN ID (1-4094)"),
  name: z.string().min(1).max(32).regex(
    /^[A-Za-z0-9_.-]+$/,
    "VLAN name may contain only letters, digits, underscore, dot, and hyphen",
  ).describe("VLAN name, e.g. USER_DATA"),
  sviIp: Ipv4Schema.optional().describe(
    "SVI gateway IP for this VLAN. Omit for an L2-only VLAN (no routed interface).",
  ),
  sviMask: NetmaskSchema.optional().describe(
    "SVI subnet mask, e.g. 255.255.255.0. Required when sviIp is set.",
  ),
}).refine((vlan) => Boolean(vlan.sviIp) === Boolean(vlan.sviMask), {
  message: "sviIp and sviMask must either both be set or both be omitted",
});

/** An access-port range and the VLAN its members are placed in. */
const AccessPortRangeSchema = z.object({
  range: z.string().min(1).max(100).regex(
    /^[A-Za-z][A-Za-z0-9./ -]*$/,
    "Interface range contains unsupported characters",
  ).describe(
    "Interface range as IOS expects it, e.g. 'fastEthernet 0/1 - 12' or 'gigabitEthernet 1/0/1 - 12'.",
  ),
  vlanId: z.number().int().min(1).max(4094).describe(
    "Access VLAN assigned to the range",
  ),
  description: SingleLineTextSchema.or(z.literal("")).describe(
    "Port description",
  ),
  portfast: z.boolean().describe(
    "Enable spanning-tree portfast on the range (edge ports)",
  ),
});

/** SNMPv2c communities and identity. Community strings are vault-resolved secrets. */
const SnmpSchema = z.object({
  readOnly: SnmpCommunitySchema.optional().meta({ sensitive: true }).describe(
    "SNMPv2c read-only community. Use: ${{ vault.get(your-vault, <switch>-snmp-ro) }}",
  ),
  readWrite: SnmpCommunitySchema.optional().meta({ sensitive: true }).describe(
    "SNMPv2c read-write community. Use: ${{ vault.get(your-vault, <switch>-snmp-rw) }}",
  ),
  location: SingleLineTextSchema.optional().describe(
    "snmp-server location string",
  ),
  contact: SingleLineTextSchema.optional().describe(
    "snmp-server contact string",
  ),
  trapHost: HostSchema.optional().describe(
    "Trap destination IP (manager/monitor). When set, traps are enabled to this host using the read-only community.",
  ),
}).refine((snmp) => !snmp.trapHost || Boolean(snmp.readOnly), {
  message: "trapHost requires readOnly so the trap community is defined",
});

/** Layer-3 intent: enable routing, create routed VLANs/SVIs, a default route, and access-port assignments. */
const RoutingSchema = z.object({
  enabled: z.boolean().describe(
    "Run 'ip routing'. Many 2960 variants do not support this — confirm the model/IOS feature set first.",
  ),
  defaultRouteNextHop: Ipv4Schema.optional().describe(
    "Next-hop for 'ip route 0.0.0.0 0.0.0.0 <next-hop>' (used when routing is enabled).",
  ),
  vlans: z.array(VlanSchema).max(4094).describe(
    "VLANs to create (with optional SVIs)",
  ),
  accessPorts: z.array(AccessPortRangeSchema).max(1024).describe(
    "Access-port ranges to assign to VLANs",
  ),
}).superRefine((routing, context) => {
  if (!routing.enabled && routing.defaultRouteNextHop) {
    context.addIssue({
      code: "custom",
      path: ["defaultRouteNextHop"],
      message: "defaultRouteNextHop requires enabled=true",
    });
  }
  const vlanIds = new Set<number>();
  for (const [index, vlan] of routing.vlans.entries()) {
    if (vlanIds.has(vlan.id)) {
      context.addIssue({
        code: "custom",
        path: ["vlans", index, "id"],
        message: `Duplicate VLAN ID ${vlan.id}`,
      });
    }
    vlanIds.add(vlan.id);
  }
});

/**
 * Global arguments for a managed Cisco IOS switch: SSH connection
 * facts plus the per-switch baseline this model asserts over SSH.
 */
export const CiscoIosGlobalArgsSchema = z.object({
  host: HostSchema.optional().describe(
    "Management IP or hostname of the switch. Omit on a bare fleet instance — discoverFleet supplies it per target.",
  ),
  port: z.number().int().min(1).max(65535).default(22).describe("SSH port"),
  username: z.string().min(1).regex(
    /^[A-Za-z0-9._-]+$/,
    "Username may contain only letters, digits, dot, underscore, and hyphen",
  ).optional().describe(
    "SSH username (a privilege-15 local user). Omit on a bare fleet instance.",
  ),
  password: VaultValueSchema.optional().meta({ sensitive: true }).describe(
    "SSH password. Use: ${{ vault.get(your-vault, <switch>-admin) }}. Omit on a bare fleet instance.",
  ),
  enableSecret: VaultValueSchema.optional().meta({ sensitive: true }).describe(
    "Enable secret. Set ONLY if the login does not land in privileged EXEC; sends 'enable' + this secret. Leave unset for a privilege-15 login.",
  ),
  hostname: CiscoHostnameSchema.optional().describe(
    "Hostname asserted by applyBaseline (does not rename the SSH target).",
  ),
  domainName: DomainNameSchema.optional().describe(
    "IP domain-name asserted by applyBaseline.",
  ),
  hostKeyPolicy: z.enum(["strict", "insecure"]).default("insecure").describe(
    "Host-key verification policy. Use strict whenever a trusted known_hosts entry is available; insecure is an explicit compatibility opt-out.",
  ),
  legacyAlgorithms: z.boolean().default(true).describe(
    "Append legacy SSH kex/cipher/host-key algorithms to the offer for old IOS images.",
  ),
  commandTimeoutMs: z.number().int().min(1000).max(300_000).default(20_000)
    .describe(
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

/** One named Cisco IOS switch target in a discoverFleet run. */
export const CiscoFleetTargetSchema = z.object({
  name: z.string().trim().min(1).max(128).regex(
    /^[A-Za-z0-9][A-Za-z0-9._-]*$/,
    "name must start with a letter or digit and contain only letters, digits, dot, underscore, or hyphen",
  ).describe(
    "Stable device name/identifier used as the resource-instance stem.",
  ),
  class: z.literal("cisco_ios_switch").describe(
    "Device class discriminator for the fleet-discovery contract.",
  ),
  host: HostSchema.describe("Management IP or hostname of the switch"),
  port: z.number().int().min(1).max(65535).default(22).describe("SSH port"),
  username: z.string().min(1).regex(
    /^[A-Za-z0-9._-]+$/,
    "Username may contain only letters, digits, dot, underscore, and hyphen",
  ).describe("SSH username (a privilege-15 local user)"),
  password: VaultValueSchema.meta({ sensitive: true }).describe(
    "SSH password. Use: ${{ vault.get(your-vault, <switch>-admin) }}",
  ),
  hostKeyPolicy: z.enum(["strict", "insecure"]).default("insecure").describe(
    "Host-key verification policy for this target.",
  ),
  legacyAlgorithms: z.boolean().default(true).describe(
    "Append legacy SSH kex/cipher/host-key algorithms to the offer for this target.",
  ),
  commandTimeoutMs: z.number().int().min(1000).max(300_000).default(20_000)
    .describe(
      "SSH connect timeout and per-session read budget, in milliseconds.",
    ),
});

export type CiscoFleetTarget = z.infer<typeof CiscoFleetTargetSchema>;

/** A unit of work for one SSH session. */
export interface IosPlan {
  /** EXEC/show commands run for their output (not inside config mode). */
  execCommands?: string[];
  /** Lines run inside `configure terminal` … `end`. */
  configLines?: string[];
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

/** Minimal child-process surface used by the injectable OpenSSH boundary. */
export interface IosChildProcess {
  stdin: WritableStream<Uint8Array>;
  stdout: ReadableStream<Uint8Array>;
  stderr: ReadableStream<Uint8Array>;
  status: Promise<Deno.CommandStatus>;
}

/** Injectable subprocess factory for deterministic transport tests. */
export type IosSpawn = (
  command: string,
  options: Deno.CommandOptions,
) => IosChildProcess;

const spawnDenoCommand: IosSpawn = (command, options) =>
  new Deno.Command(command, options).spawn();

/** IOS syslog lines are asynchronous notifications, not command rejections. */
const IOS_SYSLOG_RE = /^%[A-Z0-9_]+-\d-[A-Z0-9_]+:/;
const IOS_EXEC_ERROR_RE =
  /^%\s+(?:invalid|incomplete|ambiguous|unrecognized|unknown|bad|cannot|error|not a valid|duplicate|overlaps|authorization|access denied|command rejected|vlan\b.*does not exist)/i;
const IOS_PROMPT_RE = /(?:^|\n)[^\r\n]+[>#]\s*$/;
const ENCODER = new TextEncoder();

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

/** Build the OpenSSH argv without placing credentials on the command line. */
export function buildSshArgs(
  args: CiscoIosGlobalArgs,
  connectSecs: number,
): string[] {
  const sshArgs = [
    "-tt",
    "-p",
    String(args.port),
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
  if (args.hostKeyPolicy === "insecure") {
    sshArgs.push(
      "-o",
      "StrictHostKeyChecking=no",
      "-o",
      "UserKnownHostsFile=/dev/null",
      "-o",
      "GlobalKnownHostsFile=/dev/null",
    );
  } else {
    sshArgs.push("-o", "StrictHostKeyChecking=yes");
  }
  if (args.legacyAlgorithms) sshArgs.push(...legacyAlgoFlags());
  sshArgs.push("--", `${args.username}@${args.host}`);
  return sshArgs;
}

/** Lines fed to the IOS VTY for a plan, in order. */
function buildScript(plan: IosPlan): string[] {
  const lines: string[] = [];
  lines.push("terminal length 0", "terminal width 0");
  for (const c of plan.execCommands ?? []) lines.push(c);
  if (plan.configLines && plan.configLines.length > 0) {
    lines.push("configure terminal", ...plan.configLines, "end");
  }
  lines.push("exit");
  return lines;
}

/**
 * Open one SSH session to the switch and run a plan: optional EXEC
 * commands (captured) and/or a `configure terminal` block. Saving is a
 * separate, subsequent session so rejected configuration is never
 * persisted. Throws on connect/auth failure, session timeout, or any IOS
 * rejection line in the output. Returns the transcript and per-command
 * EXEC output.
 */
export async function runIosSession(
  args: CiscoIosGlobalArgs,
  plan: IosPlan,
  spawn: IosSpawn = spawnDenoCommand,
): Promise<IosResult> {
  const { host, username, password } = args;
  if (!host || !username || !password) {
    throw new Error(
      "runIosSession requires host, username, and password on globalArgs",
    );
  }
  const sent = buildScript(plan);
  const script = sent.join("\n") + "\n";

  // Hand the password to ssh via a private askpass helper — never argv.
  const tmp = await Deno.makeTempDir({ prefix: "ios-ssh-" });
  const pwFile = `${tmp}/pw`;
  const askpass = `${tmp}/askpass.sh`;
  try {
    await Deno.writeTextFile(pwFile, password);
    await Deno.chmod(pwFile, 0o600);
    await Deno.writeTextFile(
      askpass,
      '#!/bin/sh\ncat "$SWAMP_ASKPASS_PASSWORD_FILE"\n',
    );
    await Deno.chmod(askpass, 0o700);

    const connectSecs = Math.max(1, Math.ceil(args.commandTimeoutMs / 1000));
    const sshArgs = buildSshArgs(args, connectSecs);

    // The configured timeout is a hard wall for the complete SSH session.
    const overallMs = args.commandTimeoutMs;
    const ac = new AbortController();
    const killer = setTimeout(() => ac.abort(), overallMs);

    let output: Deno.CommandStatus & {
      stdout: Uint8Array<ArrayBufferLike>;
      stderr: Uint8Array<ArrayBufferLike>;
    };
    try {
      const child = spawn("ssh", {
        args: sshArgs,
        env: {
          SSH_ASKPASS: askpass,
          SSH_ASKPASS_REQUIRE: "force",
          SWAMP_ASKPASS_PASSWORD_FILE: pwFile,
          DISPLAY: ":0",
        },
        stdin: "piped",
        stdout: "piped",
        stderr: "piped",
        signal: ac.signal,
      });
      const writer = child.stdin.getWriter();
      const stdoutReader = child.stdout.getReader();
      const stdoutChunks: Uint8Array[] = [];
      const stderrPromise = readAll(child.stderr.getReader(), []);
      try {
        if (args.enableSecret) {
          const initial = await readUntil(
            stdoutReader,
            stdoutChunks,
            IOS_PROMPT_RE,
            "initial IOS prompt",
          );
          if (initial.trimEnd().endsWith(">")) {
            await writer.write(ENCODER.encode("enable\n"));
            await readUntil(
              stdoutReader,
              stdoutChunks,
              /Password:\s*$/i,
              "enable password prompt",
            );
            await writer.write(ENCODER.encode(`${args.enableSecret}\n`));
            const privileged = await readUntil(
              stdoutReader,
              stdoutChunks,
              IOS_PROMPT_RE,
              "privileged IOS prompt",
            );
            if (!privileged.trimEnd().endsWith("#")) {
              throw new Error(
                "IOS privilege elevation did not reach enable mode",
              );
            }
          }
        }
        await writer.write(ENCODER.encode(script));
        // Do NOT close stdin before reading the reply. With a forced PTY
        // (`ssh -tt`), EOF tears down the interactive IOS VTY before it
        // finishes the script. The final `exit` closes the remote session;
        // the AbortController is the backstop for a device that never exits.
        const stdout = await readAll(stdoutReader, stdoutChunks);
        const [status, stderr] = await Promise.all([
          child.status,
          stderrPromise,
        ]);
        output = { ...status, stdout, stderr };
      } finally {
        await writer.close().catch(() => {});
        writer.releaseLock();
        stdoutReader.releaseLock();
      }
    } catch (e) {
      if (ac.signal.aborted) {
        throw new Error(
          `SSH session to ${args.host} exceeded ${overallMs} ms and was aborted`,
        );
      }
      ac.abort();
      const message = e instanceof Error ? e.message : String(e);
      throw new Error(redactKnownSecrets(message, args));
    } finally {
      clearTimeout(killer);
    }

    const transcript = new TextDecoder().decode(output.stdout).replace(
      /\r/g,
      "",
    );
    const stderr = new TextDecoder().decode(output.stderr).trim();

    if (!output.success) {
      const why = classifySshError(stderr) ??
        (redactKnownSecrets(stderr, args) || "no stderr");
      throw new Error(
        `SSH to ${args.host} exited with code ${output.code}: ${why}`,
      );
    }

    if (transcript.trim() === "") {
      const why = classifySshError(stderr) ??
        (redactKnownSecrets(stderr, args) || "no output");
      throw new Error(`SSH to ${args.host} produced no session: ${why}`);
    }
    const authErr = classifySshError(stderr);
    if (authErr) throw new Error(`SSH to ${args.host} failed: ${authErr}`);

    const failureSurface = rejectionSurface(transcript, plan);
    const iosError = plan.configLines?.length ||
        plan.execCommands?.includes("write memory")
      ? findIosError(failureSurface)
      : findExecCommandError(failureSurface);
    if (iosError) {
      throw new Error(
        `IOS rejected a command on ${args.host}: ${
          redactKnownSecrets(iosError, args)
        }`,
      );
    }

    // Device-output redaction is selected by each public method. Transport
    // credentials are different: they must never escape even if an operator
    // explicitly requests raw device data.
    const redactedTranscript = redactTransportSecrets(transcript, args);
    return {
      transcript: redactedTranscript,
      execOutputs: sliceExecOutputs(
        redactedTranscript,
        sent,
        plan.execCommands ?? [],
      ),
    };
  } finally {
    await Deno.remove(tmp, { recursive: true }).catch(() => {});
  }
}

async function readUntil(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  chunks: Uint8Array[],
  pattern: RegExp,
  label: string,
): Promise<string> {
  while (true) {
    const { value, done } = await reader.read();
    if (done) throw new Error(`SSH session ended before ${label}`);
    chunks.push(value);
    const text = new TextDecoder().decode(concatBytes(chunks)).replace(
      /\r/g,
      "",
    );
    if (pattern.test(text)) return text;
  }
}

async function readAll(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  chunks: Uint8Array[],
): Promise<Uint8Array> {
  while (true) {
    const { value, done } = await reader.read();
    if (done) return concatBytes(chunks);
    chunks.push(value);
  }
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(
    chunks.reduce((length, chunk) => length + chunk.length, 0),
  );
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

function rejectionSurface(transcript: string, plan: IosPlan): string {
  const anchor = plan.configLines?.length
    ? "configure terminal"
    : plan.execCommands?.[0];
  if (!anchor) return transcript;
  const position = transcript.indexOf(anchor);
  return position === -1 ? transcript : transcript.slice(position);
}

function findExecCommandError(output: string): string | null {
  for (const raw of output.split(/\r?\n/)) {
    const line = raw.trim();
    if (IOS_EXEC_ERROR_RE.test(line)) return line;
  }
  return null;
}

function redactKnownSecrets(
  value: string,
  args: CiscoIosGlobalArgs,
): string {
  return redactValues(value, [
    args.password ?? "",
    args.enableSecret ?? "",
    args.snmp?.readOnly ?? "",
    args.snmp?.readWrite ?? "",
  ]);
}

function redactTransportSecrets(
  value: string,
  args: CiscoIosGlobalArgs,
): string {
  return redactValues(value, [args.password ?? "", args.enableSecret ?? ""]);
}

function redactValues(value: string, values: string[]): string {
  const secrets = [...new Set(values.filter(Boolean))].sort((left, right) =>
    right.length - left.length
  );
  return secrets.reduce(
    (redacted, secret) =>
      secret ? redacted.replaceAll(secret, "***") : redacted,
    value,
  );
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
    return "algorithm negotiation failed";
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
    // Fail closed on every percent-prefixed CLI response except structured
    // `%FACILITY-SEVERITY-MNEMONIC:` syslog notifications, which can arrive
    // asynchronously during an otherwise successful session.
    if (line.startsWith("%") && !IOS_SYSLOG_RE.test(line)) return line;
  }
  return null;
}
