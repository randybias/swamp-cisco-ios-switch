import { z } from "npm:zod@4.3.6";
import {
  type CiscoFleetTarget,
  CiscoFleetTargetSchema,
  type CiscoIosBaseline,
  CiscoIosBaselineSchema,
  type CiscoIosConnection,
  CiscoIosConnectionSchema,
  type CiscoIosGlobalArgs,
  CiscoIosGlobalArgsSchema,
  type CiscoIosRoutingPayload,
  CiscoIosRoutingPayloadSchema,
  type CiscoIosSnmpPayload,
  CiscoIosSnmpPayloadSchema,
  findIosError,
  runIosSession,
} from "./_ssh.ts";
import {
  baselineLines,
  parseMacAddressTable,
  parseShowVersion,
  redactCommandOutput,
  redactConfig,
  redactLine,
  routingLines,
  snmpLines,
} from "./_config.ts";

const ReadOnlyCommandSchema = z.string().transform((command) => command.trim())
  .refine(
    (command) =>
      /^show(?:\s|$)/i.test(command) &&
      !command.includes(">") &&
      !/\|\s*(?:append|redirect|tee)(?:\s|$)/i.test(command) &&
      ![...command].some((character) => {
        const code = character.codePointAt(0)!;
        return character === ";" || code < 32 || code === 127;
      }),
    "Each command must be a single read-only show command without output redirection",
  );

/** Per-target outcome of one discoverFleet run. */
export interface FleetTargetResult {
  name: string;
  host: string;
  ok: boolean;
  error?: string;
}

const FleetSummarySchema = z.object({
  capturedAt: z.iso.datetime(),
  total: z.number().int(),
  succeeded: z.number().int(),
  failed: z.number().int(),
  results: z.array(z.object({
    name: z.string(),
    host: z.string(),
    ok: z.boolean(),
    error: z.string().optional(),
  })),
});

const FleetArgumentsSchema = z.object({
  targets: z.array(CiscoFleetTargetSchema).min(1).max(64).describe(
    "Named Cisco IOS switch targets to discover in this run.",
  ),
}).superRefine(({ targets }, context) => {
  const names = new Set<string>();
  for (const [index, target] of targets.entries()) {
    if (names.has(target.name)) {
      context.addIssue({
        code: "custom",
        path: ["targets", index, "name"],
        message: `duplicate target name '${target.name}'`,
      });
    }
    names.add(target.name);
  }
});

/** Roll one fleet run's outcomes into a deterministic pass/fail summary. */
function summarizeFleetResults(results: FleetTargetResult[]): {
  total: number;
  succeeded: number;
  failed: number;
  results: FleetTargetResult[];
} {
  const succeeded = results.filter((r) => r.ok).length;
  return {
    total: results.length,
    succeeded,
    failed: results.length - succeeded,
    results,
  };
}

/** Redact one credential defensively from a recorded failure message. */
function redactTargetSecret(value: string, secret: string): string {
  return secret.length > 0 ? value.replaceAll(secret, "***") : value;
}

/** Injectable boundaries used by model entrypoint and failure-path tests. */
export interface CiscoIosModelDependencies {
  runSession: typeof runIosSession;
  probeTcp: typeof probeTcp;
  now: () => Date;
}

/** Migrate existing published definitions while preserving their old transport behavior. */
export function upgradeGlobalArguments(
  old: Record<string, unknown>,
): Record<string, unknown> {
  const upgraded: Record<string, unknown> = {
    ...old,
    port: old.port ?? 22,
    hostKeyPolicy: old.hostKeyPolicy ?? "insecure",
    legacyAlgorithms: old.legacyAlgorithms ?? true,
    commandTimeoutMs: old.commandTimeoutMs ?? 20_000,
  };
  if (old.snmp && typeof old.snmp === "object") {
    const snmp = { ...(old.snmp as Record<string, unknown>) };
    // The published generator ignored trapHost unless readOnly existed. The
    // hardened schema makes that dependency explicit, so discard an
    // ineffective legacy trapHost rather than invalidating the definition.
    if (snmp.trapHost && !snmp.readOnly) delete snmp.trapHost;
    upgraded.snmp = snmp;
  }
  if (old.routing && typeof old.routing === "object") {
    const routing = old.routing as Record<string, unknown>;
    const enabled = routing.enabled ?? false;
    const vlans = Array.isArray(routing.vlans)
      ? routing.vlans.map((value) => {
        if (!value || typeof value !== "object") return value;
        const vlan = { ...(value as Record<string, unknown>) };
        if (Boolean(vlan.sviIp) !== Boolean(vlan.sviMask)) {
          delete vlan.sviIp;
          delete vlan.sviMask;
        }
        return vlan;
      })
      : [];
    const accessPorts = Array.isArray(routing.accessPorts)
      ? routing.accessPorts.map((value) => {
        if (!value || typeof value !== "object") return value;
        const accessPort = value as Record<string, unknown>;
        return {
          ...accessPort,
          description: accessPort.description ?? "",
          portfast: accessPort.portfast ?? true,
        };
      })
      : [];
    upgraded.routing = {
      ...routing,
      enabled,
      defaultRouteNextHop: enabled ? routing.defaultRouteNextHop : undefined,
      vlans,
      accessPorts,
    };
  }
  return upgraded;
}

/*
 * `requireGlobalConnection` was here and is GONE (2026-09-05).
 *
 * It narrowed `globalArgs` into a usable connection for the five single-target
 * methods. Those take a `connection` ARGUMENT now, validated before any code
 * runs, so the guard has nothing left to guard.
 */

/**
 * `@dougschaefer/cisco-ios-switch` model — manages a Cisco IOS switch
 * (e.g. Catalyst 2960) over SSH after it has been bootstrapped at the
 * console. It drives the interactive VTY the way an operator would.
 *
 * `getRunningConfig` captures the running config (secrets redacted by
 * default) plus parsed model/IOS/uptime facts. `runCommands` runs
 * validated show commands and captures redacted output — the verification
 * surface. `applyBaseline` asserts idempotent secure-access
 * hardening (hostname, domain, password encryption, HTTP off, console
 * and VTY login/timeout, SSH-only transport). `pushSnmp` configures
 * SNMPv2c read-only/read-write communities, location, contact, and an
 * optional trap host. `pushRouting` enables `ip routing`, creates
 * VLANs/SVIs, sets a default route, and assigns access-port ranges.
 *
 * It cannot reset the switch or bootstrap SSH itself — a freshly wiped
 * switch has no IP or VTY, so the first management config goes over the
 * console. This model owns everything after that.
 *
 * Mutating methods accept `dryRun` to render and store the exact IOS
 * lines without connecting. Connection facts and per-switch baseline
 * live in `globalArguments` (secrets vault-resolved).
 */
export function createCiscoIosModel(
  overrides: Partial<CiscoIosModelDependencies> = {},
) {
  const dependencies: CiscoIosModelDependencies = {
    runSession: runIosSession,
    probeTcp,
    now: () => new Date(),
    ...overrides,
  };

  return {
    type: "@dougschaefer/cisco-ios-switch",
    version: "2026.07.20.1",
    globalArguments: CiscoIosGlobalArgsSchema,
    upgrades: [
      {
        toVersion: "2026.07.19.1",
        description:
          "Require explicit transport policy for new definitions while preserving the prior port, insecure host-key, legacy-algorithm, timeout, and routing defaults on existing definitions",
        upgradeAttributes: upgradeGlobalArguments,
      },
      {
        toVersion: "2026.07.20.1",
        description:
          "host/username/password become optional (a bare fleet instance has neither); port/hostKeyPolicy/legacyAlgorithms/commandTimeoutMs are now schema-level defaults instead of required fields — existing values are preserved unchanged",
        upgradeAttributes: (old: Record<string, unknown>) => old,
      },
    ],
    resources: {
      status: {
        description:
          "Parsed device facts: hostname, model, IOS version, uptime",
        schema: z.object({
          host: z.string(),
          hostname: z.string(),
          model: z.string(),
          iosVersion: z.string(),
          uptime: z.string(),
          capturedAt: z.iso.datetime(),
        }),
        lifetime: "7d",
        garbageCollection: 5,
      },
      commandResult: {
        description: "Captured output of ad-hoc EXEC/show commands",
        schema: z.object({
          host: z.string(),
          commands: z.array(z.object({
            command: z.string(),
            output: z.string(),
          })),
          capturedAt: z.iso.datetime(),
        }),
        lifetime: "7d",
        garbageCollection: 5,
      },
      macTable: {
        description:
          "Parsed `show mac address-table` rows -- the out-of-band liveness witness. A DYNAMIC entry proves the device behind that MAC is powered and transmitting, without touching the device.",
        schema: z.object({
          host: z.string(),
          rows: z.array(z.object({
            vlan: z.string(),
            mac: z.string(),
            type: z.string(),
            ports: z.array(z.string()),
          })),
          dynamicCount: z.number(),
          totalCount: z.number(),
          capturedAt: z.iso.datetime(),
        }),
        lifetime: "7d",
        garbageCollection: 5,
      },
      pushResult: {
        description:
          "Result of a configuration push: the applied IOS lines and whether it saved",
        schema: z.object({
          host: z.string(),
          method: z.string(),
          appliedLines: z.array(z.string()),
          saved: z.boolean(),
          dryRun: z.boolean(),
          deviceOutput: z.string(),
          appliedAt: z.iso.datetime(),
        }),
        lifetime: "30d",
        garbageCollection: 10,
      },
      fleetSummary: {
        description:
          "Per-target pass/fail summary of the most recent discoverFleet fan-out run",
        schema: FleetSummarySchema,
        lifetime: "7d",
        garbageCollection: 5,
      },
    },
    files: {
      runningConfig: {
        description:
          "Captured running-config (secrets redacted unless redactSecrets=false)",
        contentType: "text/plain",
        lifetime: "7d",
        garbageCollection: 5,
      },
    },
    methods: {
      getRunningConfig: {
        description:
          "Capture 'show running-config' and 'show version'; store the config file and parsed device facts. Read-only.",
        arguments: z.object({
          // The connection is a METHOD argument, not globalArgs, since 2026-09-05:
          // globalArguments cannot be supplied per step, so these methods could not
          // be aimed at any switch or given a credential.
          connection: CiscoIosConnectionSchema,
          redactSecrets: z.boolean().default(true).describe(
            "Strip community strings, secrets, and password lines before storing the config file.",
          ),
        }),
        execute: async (
          args: { redactSecrets: boolean; connection: CiscoIosConnection },
          context: MethodContext,
        ) => {
          const g = args.connection;
          context.logger.info("Capturing running-config from {host}", {
            host: g.host,
          });
          const result = await dependencies.runSession(g, {
            execCommands: ["show version", "show running-config"],
          });
          const version = requiredOutput(result.execOutputs, "show version");
          const config = requiredOutput(
            result.execOutputs,
            "show running-config",
          );
          const facts = parseShowVersion(version);

          const cfgWriter = context.createFileWriter(
            "runningConfig",
            `${g.host}-running`,
          );
          const cfgHandle = await cfgWriter.writeText(
            args.redactSecrets ? redactConfig(config) : config,
          );

          const statusHandle = await context.writeResource(
            "status",
            `${g.host}-status`,
            {
              host: g.host,
              hostname: facts.hostname,
              model: facts.model,
              iosVersion: facts.iosVersion,
              uptime: facts.uptime,
              capturedAt: dependencies.now().toISOString(),
            },
          );
          context.logger.info(
            "Captured {model} running {version} from {host}",
            {
              model: facts.model || "unknown",
              version: facts.iosVersion || "unknown",
              host: g.host,
            },
          );
          return { dataHandles: [cfgHandle, statusHandle] };
        },
      },

      runCommands: {
        description:
          "Run validated single-line show commands and capture their output with known configuration secrets redacted by default. Newlines, semicolons, non-show commands, and device-storage redirection are rejected.",
        arguments: z.object({
          // The connection is a METHOD argument, not globalArgs, since 2026-09-05:
          // globalArguments cannot be supplied per step, so these methods could not
          // be aimed at any switch or given a credential.
          connection: CiscoIosConnectionSchema,
          commands: z.array(ReadOnlyCommandSchema).min(1).max(100).describe(
            "Read-only show commands to run",
          ),
          redactSecrets: z.boolean().default(true).describe(
            "Redact known IOS configuration secrets from captured output.",
          ),
        }),
        execute: async (
          args: {
            commands: string[];
            redactSecrets: boolean;
            connection: CiscoIosConnection;
          },
          context: MethodContext,
        ) => {
          const g = args.connection;
          context.logger.info("Running {count} command(s) on {host}", {
            count: args.commands.length,
            host: g.host,
          });
          const result = await dependencies.runSession(g, {
            execCommands: args.commands,
          });
          const commands = args.redactSecrets
            ? result.execOutputs.map(({ command, output }) => ({
              command,
              output: redactCommandOutput(output),
            }))
            : result.execOutputs;
          const handle = await context.writeResource(
            "commandResult",
            `${g.host}-cmds`,
            {
              host: g.host,
              commands,
              capturedAt: dependencies.now().toISOString(),
            },
          );
          context.logger.info(
            "Captured output for {count} command(s) on {host}",
            {
              count: commands.length,
              host: g.host,
            },
          );
          return { dataHandles: [handle] };
        },
      },

      getMacTable: {
        description:
          "Read `show mac address-table` and return it parsed, with every MAC normalized to the colon-separated LOWERCASE form of the inventory DB's canonical mac_address table (measured 249/249 rows; note lldp_neighbor.remote_chassis_mac is UPPERCASE, so a caller joining against THAT table must fold the case itself -- there is no single DB-wide MAC form). Read-only. This is the OUT-OF-BAND LIVENESS WITNESS: a DYNAMIC entry proves the device behind that MAC is powered and transmitting, established from the switch without touching the device at all -- so it still answers when the device's own management address does not. That distinction is the point. An address that does not respond is indistinguishable from a dead device UNTIL you have this: on 2026-08-21 an iDRAC was diagnosed as dead when it had merely moved VLAN, and its MAC was being learned dynamically on the OOB switch port the entire time. Entry TYPE is returned rather than reduced to a boolean, because only DYNAMIC proves current transmission -- STATIC is configuration and the CPU rows are the switch describing itself; counting either as liveness would manufacture evidence. This method reports the table and draws NO conclusion about any device.",
        arguments: z.object({
          // The connection is a METHOD argument, not globalArgs, since 2026-09-05.
          // This method also had an EMPTY schema, which drops every input silently —
          // the shape that made a napalm caller's five inputs vanish.
          connection: CiscoIosConnectionSchema,
        }),
        execute: async (
          args: { connection: CiscoIosConnection },
          context: MethodContext,
        ) => {
          const g = args.connection;
          context.logger.info("Reading MAC address-table from {host}", {
            host: g.host,
          });
          const result = await dependencies.runSession(g, {
            execCommands: ["show mac address-table"],
          });
          const text = result.execOutputs.map((o) => o.output).join("\n");
          const rows = parseMacAddressTable(text);
          const dynamicCount = rows.filter((r) => r.type === "DYNAMIC").length;
          const handle = await context.writeResource(
            "macTable",
            `${g.host}-mac-table`,
            {
              host: g.host,
              rows,
              dynamicCount,
              totalCount: rows.length,
              capturedAt: dependencies.now().toISOString(),
            },
          );
          context.logger.info(
            "Parsed {total} MAC entries from {host} ({dynamic} dynamic)",
            { total: rows.length, dynamic: dynamicCount, host: g.host },
          );
          return { dataHandles: [handle] };
        },
      },

      applyBaseline: {
        description:
          "Assert idempotent secure-access hardening: hostname/domain, service password-encryption, HTTP off, console + VTY login/timeout, SSH-only transport. Saves to startup.",
        arguments: z.object({
          // The connection is a METHOD argument, not globalArgs, since 2026-09-05:
          // globalArguments cannot be supplied per step, so these methods could not
          // be aimed at any switch or given a credential.
          connection: CiscoIosConnectionSchema,
          ...CiscoIosBaselineSchema.shape,
          dryRun: z.boolean().describe(
            "Required safety choice: true renders without connecting; false applies and saves on the switch.",
          ),
        }),
        execute: async (
          args: {
            dryRun: boolean;
            connection: CiscoIosConnection;
            hostname?: CiscoIosBaseline["hostname"];
            domainName?: CiscoIosBaseline["domainName"];
          },
          context: MethodContext,
        ) => {
          const g = args.connection;
          logMutationEntry(context, "applyBaseline", args.dryRun);
          const lines = baselineLines({
            hostname: args.hostname,
            domainName: args.domainName,
          });
          return await applyConfig(
            context,
            "applyBaseline",
            lines,
            args.dryRun,
            false,
            dependencies,
            g,
          );
        },
      },

      pushSnmp: {
        description:
          "Configure SNMPv2c read-only/read-write communities, location, contact, and optional trap host from globalArguments.snmp. Saves to startup.",
        arguments: z.object({
          // The connection is a METHOD argument, not globalArgs, since 2026-09-05:
          // globalArguments cannot be supplied per step, so these methods could not
          // be aimed at any switch or given a credential.
          connection: CiscoIosConnectionSchema,
          ...CiscoIosSnmpPayloadSchema.shape,
          dryRun: z.boolean().describe(
            "Required safety choice: true renders without connecting; false applies and saves on the switch.",
          ),
        }),
        execute: async (
          args: {
            dryRun: boolean;
            connection: CiscoIosConnection;
            snmp: CiscoIosSnmpPayload["snmp"];
          },
          context: MethodContext,
        ) => {
          const g = args.connection;
          logMutationEntry(context, "pushSnmp", args.dryRun);
          if (!args.snmp || (!args.snmp.readOnly && !args.snmp.readWrite)) {
            throw new Error(
              "the snmp argument must define at least one of readOnly / readWrite",
            );
          }
          const lines = snmpLines({ snmp: args.snmp });
          // Redact community strings from the stored record (secrets).
          return await applyConfig(
            context,
            "pushSnmp",
            lines,
            args.dryRun,
            true,
            dependencies,
            g,
          );
        },
      },

      pushRouting: {
        description:
          "Apply Layer-3 intent from globalArguments.routing: ip routing, VLANs/SVIs, default route, and access-port assignments. Saves to startup.",
        arguments: z.object({
          // The connection is a METHOD argument, not globalArgs, since 2026-09-05:
          // globalArguments cannot be supplied per step, so these methods could not
          // be aimed at any switch or given a credential.
          connection: CiscoIosConnectionSchema,
          ...CiscoIosRoutingPayloadSchema.shape,
          dryRun: z.boolean().describe(
            "Required safety choice: true renders without connecting; false applies and saves on the switch.",
          ),
        }),
        execute: async (
          args: {
            dryRun: boolean;
            connection: CiscoIosConnection;
            routing: CiscoIosRoutingPayload["routing"];
          },
          context: MethodContext,
        ) => {
          const g = args.connection;
          logMutationEntry(context, "pushRouting", args.dryRun);
          if (!args.routing) {
            throw new Error("the routing argument is required for pushRouting");
          }
          const lines = routingLines({ routing: args.routing });
          if (lines.length === 0) {
            throw new Error("the routing argument produced no configuration");
          }
          return await applyConfig(
            context,
            "pushRouting",
            lines,
            args.dryRun,
            false,
            dependencies,
            g,
          );
        },
      },

      discoverFleet: {
        description:
          "Discover a named array of Cisco IOS switch targets in one execution. Each target is TCP-probed, then captures show version + running-config + LLDP neighbor detail in one SSH session; failures are recorded without aborting the remaining fleet. Read-only.",
        arguments: FleetArgumentsSchema,
        execute: async (
          args: { targets: CiscoFleetTarget[] },
          context: MethodContext,
        ) => {
          const handles: DataHandle[] = [];
          const results: FleetTargetResult[] = [];
          context.logger.info(
            "Starting IOS discovery for {count} target(s)",
            { count: args.targets.length },
          );

          for (const target of args.targets) {
            try {
              await dependencies.probeTcp(
                target.host,
                target.port,
                Math.max(3000, Math.min(target.commandTimeoutMs, 10000)),
              );
              const sessionArgs: CiscoIosConnection = {
                host: target.host,
                port: target.port,
                username: target.username,
                password: target.password,
                hostKeyPolicy: target.hostKeyPolicy,
                legacyAlgorithms: target.legacyAlgorithms,
                commandTimeoutMs: target.commandTimeoutMs,
              };
              const result = await dependencies.runSession(sessionArgs, {
                execCommands: [
                  "show version",
                  "show running-config",
                  "show lldp neighbors detail",
                ],
              });
              const version = requiredOutput(
                result.execOutputs,
                "show version",
              );
              const config = requiredOutput(
                result.execOutputs,
                "show running-config",
              );
              const lldp = requiredOutput(
                result.execOutputs,
                "show lldp neighbors detail",
              );
              const facts = parseShowVersion(version);

              const cfgHandle = await context.createFileWriter(
                "runningConfig",
                `${target.name}-running`,
              ).writeText(redactConfig(config));
              const statusHandle = await context.writeResource(
                "status",
                `${target.name}-status`,
                {
                  host: target.host,
                  hostname: facts.hostname,
                  model: facts.model,
                  iosVersion: facts.iosVersion,
                  uptime: facts.uptime,
                  capturedAt: dependencies.now().toISOString(),
                },
              );
              const lldpHandle = await context.writeResource(
                "commandResult",
                `${target.name}-cmds`,
                {
                  host: target.host,
                  commands: [{
                    command: "show lldp neighbors detail",
                    output: redactCommandOutput(lldp),
                  }],
                  capturedAt: dependencies.now().toISOString(),
                },
              );
              handles.push(cfgHandle, statusHandle, lldpHandle);
              results.push({ name: target.name, host: target.host, ok: true });
              context.logger.info(
                "Captured {model} running {version} from {name} ({host})",
                {
                  model: facts.model || "unknown",
                  version: facts.iosVersion || "unknown",
                  name: target.name,
                  host: target.host,
                },
              );
            } catch (e) {
              const error = redactTargetSecret(
                redactTargetSecret(
                  e instanceof Error ? e.message : String(e),
                  target.password,
                ),
                target.username,
              );
              results.push({
                name: target.name,
                host: target.host,
                ok: false,
                error,
              });
              context.logger.info(
                "Skipping {name} ({host}) after a discovery failure: {error}",
                { name: target.name, host: target.host, error },
              );
            }
          }

          const summary = summarizeFleetResults(results);
          const summaryHandle = await context.writeResource(
            "fleetSummary",
            "fleet-summary",
            { ...summary, capturedAt: dependencies.now().toISOString() },
          );
          context.logger.info(
            "Fleet discovery complete: {succeeded}/{total} succeeded",
            { succeeded: summary.succeeded, total: summary.total },
          );
          return { dataHandles: [...handles, summaryHandle] };
        },
      },
    },
    checks: {
      "switch-reachable": {
        description:
          "TCP-probe the configured switch SSH port before running a method.",
        labels: ["live"],
        appliesTo: [
          "getRunningConfig",
          "runCommands",
          "applyBaseline",
          "pushSnmp",
          "pushRouting",
        ],
        execute: async (context: CheckContext): Promise<CheckResult> => {
          const { host, port, commandTimeoutMs } = context.globalArgs;
          if (!host) {
            return {
              pass: false,
              errors: [
                "globalArguments.host is not configured on this instance — bare fleet instances have no single-target host to probe; use discoverFleet instead.",
              ],
            };
          }
          const timeoutMs = Math.max(3000, Math.min(commandTimeoutMs, 10000));
          try {
            await dependencies.probeTcp(host, port, timeoutMs);
            return { pass: true };
          } catch (e) {
            return {
              pass: false,
              errors: [
                `${host}:${port} not reachable over TCP (${
                  e instanceof Error ? e.message : String(e)
                }). Bootstrap the switch over the console first, or skip with --skip-check-label live.`,
              ],
            };
          }
        },
      },
    },
  };
}

/** Production model using the real SSH, TCP, and clock boundaries. */
export const model = createCiscoIosModel();

/** Context passed to pre-flight checks (no data-writing surface). */
interface CheckContext {
  globalArgs: CiscoIosGlobalArgs;
}
/** Pre-flight check result. */
interface CheckResult {
  pass: boolean;
  errors?: string[];
}

type TcpConnect = (
  options: Deno.ConnectOptions,
) => Promise<{ close(): void }>;

/** Open a TCP connection within `timeoutMs`, closing it (or a late one) immediately. */
export function probeTcp(
  hostname: string,
  port: number,
  timeoutMs: number,
  connect: TcpConnect = Deno.connect,
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      reject(new Error(`timed out after ${timeoutMs} ms`));
    }, timeoutMs);
    connect({ hostname, port }).then(
      (conn) => {
        clearTimeout(timer);
        conn.close();
        if (!done) {
          done = true;
          resolve();
        }
      },
      (err) => {
        clearTimeout(timer);
        if (done) return;
        done = true;
        reject(err instanceof Error ? err : new Error(String(err)));
      },
    );
  });
}

/** Minimal shape of the method context used here (see swamp model API). */
interface MethodContext {
  globalArgs: CiscoIosGlobalArgs;
  logger: {
    info: (msg: string, props?: Record<string, unknown>) => void;
  };
  writeResource: (
    spec: string,
    instance: string,
    data: Record<string, unknown>,
  ) => Promise<DataHandle>;
  createFileWriter: (
    spec: string,
    instance: string,
  ) => { writeText: (t: string) => Promise<DataHandle> };
}
interface DataHandle {
  name: string;
  specName: string;
}

/** Shared push path: optionally dry-run, otherwise apply config and save. */
async function applyConfig(
  context: MethodContext,
  method: string,
  lines: string[],
  dryRun: boolean,
  redactStored: boolean,
  dependencies: CiscoIosModelDependencies,
  // ⚠️ PASSED IN, not read from `context.globalArgs`. This helper is the one
  // place every mutating method reaches the switch, and it was reading the
  // connection from the instance -- which no run can set. Taking it as a
  // parameter is what makes the three push methods actually aimable.
  connection: CiscoIosConnection,
): Promise<{ dataHandles: DataHandle[] }> {
  const g = connection;
  const storedLines = redactStored ? lines.map(redactLine) : lines;
  if (dryRun) {
    const handle = await context.writeResource(
      "pushResult",
      `${g.host}-${method}`,
      {
        host: g.host,
        method,
        appliedLines: storedLines,
        saved: false,
        dryRun: true,
        deviceOutput: "(dry run — not connected)",
        appliedAt: dependencies.now().toISOString(),
      },
    );
    context.logger.info("Rendered {method} for {host} (dryRun=true)", {
      method,
      host: g.host,
    });
    return { dataHandles: [handle] };
  }
  const applyResult = await dependencies.runSession(g, {
    configLines: lines,
  });
  const applyError = findIosError(applyResult.transcript);
  if (applyError) throw new Error(`${method} failed: ${applyError}`);

  // Persist only after the configuration session completed without an IOS
  // rejection. This deliberately uses a second, independently verified VTY
  // session so a bad line can never be followed by `write memory` in the same
  // pre-buffered script.
  const saveResult = await dependencies.runSession(g, {
    execCommands: ["write memory"],
  });
  const saveError = findIosError(saveResult.transcript);
  if (saveError) throw new Error(`${method} save failed: ${saveError}`);
  const saveOutput = saveResult.execOutputs.find((entry) =>
    entry.command === "write memory"
  )?.output;
  if (!saveOutput || !/\[OK\]/i.test(saveOutput)) {
    throw new Error(`${method} save failed: IOS did not acknowledge [OK]`);
  }
  const transcript = `${applyResult.transcript}\n${saveResult.transcript}`;
  const handle = await context.writeResource(
    "pushResult",
    `${g.host}-${method}`,
    {
      host: g.host,
      method,
      appliedLines: storedLines,
      saved: true,
      dryRun: false,
      deviceOutput: redactStored
        ? "(suppressed — contains secrets)"
        : redactCommandOutput(tail(transcript, 2000)),
      appliedAt: dependencies.now().toISOString(),
    },
  );
  context.logger.info("Applied {method} to {host} (saved=true)", {
    method,
    host: g.host,
  });
  return { dataHandles: [handle] };
}

// ---- private helpers ----

function logMutationEntry(
  context: MethodContext,
  method: string,
  dryRun: boolean,
): void {
  context.logger.info(
    "Preparing {method} for {host} (dryRun={dryRun})",
    { method, host: context.globalArgs.host, dryRun },
  );
}

function requiredOutput(
  execOutputs: { command: string; output: string }[],
  cmd: string,
): string {
  const value = execOutputs.find((entry) => entry.command === cmd)?.output;
  if (!value?.trim()) {
    throw new Error(`SSH session returned no output for '${cmd}'`);
  }
  return value;
}

function tail(s: string, n: number): string {
  return s.length <= n ? s : s.slice(s.length - n);
}
