import { z } from "npm:zod@4.3.6";
import {
  type CiscoIosGlobalArgs,
  CiscoIosGlobalArgsSchema,
  findIosError,
  runIosSession,
} from "./_ssh.ts";
import {
  baselineLines,
  parseShowVersion,
  redactConfig,
  redactLine,
  routingLines,
  snmpLines,
} from "./_config.ts";

/**
 * `@dougschaefer/cisco-ios-switch` model — manages a Cisco IOS switch
 * (e.g. Catalyst 2960) over SSH after it has been bootstrapped at the
 * console. It drives the interactive VTY the way an operator would.
 *
 * `getRunningConfig` captures the running config (secrets redacted by
 * default) plus parsed model/IOS/uptime facts. `runCommands` runs
 * arbitrary EXEC/show commands and captures their output — the
 * verification surface. `applyBaseline` asserts idempotent secure-access
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
export const model = {
  type: "@dougschaefer/cisco-ios-switch",
  version: "2026.06.29.1",
  globalArguments: CiscoIosGlobalArgsSchema,
  resources: {
    status: {
      description: "Parsed device facts: hostname, model, IOS version, uptime",
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
        redactSecrets: z.boolean().default(true).describe(
          "Strip community strings, secrets, and password lines before storing the config file.",
        ),
      }),
      execute: async (
        args: { redactSecrets: boolean },
        context: MethodContext,
      ) => {
        const g = context.globalArgs;
        context.logger.info("Capturing running-config from {host}", {
          host: g.host,
        });
        const result = await runIosSession(g, {
          execCommands: ["show version", "show running-config"],
        });
        const version = output(result.execOutputs, "show version");
        const config = output(result.execOutputs, "show running-config");
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
            capturedAt: new Date().toISOString(),
          },
        );
        context.logger.info("Captured {model} running {version} from {host}", {
          model: facts.model || "unknown",
          version: facts.iosVersion || "unknown",
          host: g.host,
        });
        return { dataHandles: [cfgHandle, statusHandle] };
      },
    },

    runCommands: {
      description:
        "Run arbitrary EXEC/show commands and capture their output. Use for verification (e.g. 'show ip ssh', 'show ip route').",
      arguments: z.object({
        commands: z.array(z.string()).min(1).describe(
          "EXEC/show commands to run",
        ),
      }),
      execute: async (args: { commands: string[] }, context: MethodContext) => {
        const g = context.globalArgs;
        context.logger.info("Running {count} command(s) on {host}", {
          count: args.commands.length,
          host: g.host,
        });
        const result = await runIosSession(g, { execCommands: args.commands });
        const handle = await context.writeResource(
          "commandResult",
          `${g.host}-cmds`,
          {
            host: g.host,
            commands: result.execOutputs,
            capturedAt: new Date().toISOString(),
          },
        );
        context.logger.info(
          "Captured output for {count} command(s) on {host}",
          {
            count: result.execOutputs.length,
            host: g.host,
          },
        );
        return { dataHandles: [handle] };
      },
    },

    applyBaseline: {
      description:
        "Assert idempotent secure-access hardening: hostname/domain, service password-encryption, HTTP off, console + VTY login/timeout, SSH-only transport. Saves to startup.",
      arguments: z.object({
        dryRun: z.boolean().default(false),
      }),
      execute: async (args: { dryRun: boolean }, context: MethodContext) => {
        const g = context.globalArgs;
        const lines = baselineLines(g);
        return await applyConfig(
          context,
          "applyBaseline",
          lines,
          args.dryRun,
          false,
        );
      },
    },

    pushSnmp: {
      description:
        "Configure SNMPv2c read-only/read-write communities, location, contact, and optional trap host from globalArguments.snmp. Saves to startup.",
      arguments: z.object({
        dryRun: z.boolean().default(false),
      }),
      execute: async (args: { dryRun: boolean }, context: MethodContext) => {
        const g = context.globalArgs;
        if (!g.snmp || (!g.snmp.readOnly && !g.snmp.readWrite)) {
          throw new Error(
            "globalArguments.snmp must define at least one of readOnly / readWrite",
          );
        }
        const lines = snmpLines(g);
        // Redact community strings from the stored record (secrets).
        return await applyConfig(context, "pushSnmp", lines, args.dryRun, true);
      },
    },

    pushRouting: {
      description:
        "Apply Layer-3 intent from globalArguments.routing: ip routing, VLANs/SVIs, default route, and access-port assignments. Saves to startup.",
      arguments: z.object({
        dryRun: z.boolean().default(false),
      }),
      execute: async (args: { dryRun: boolean }, context: MethodContext) => {
        const g = context.globalArgs;
        if (!g.routing) {
          throw new Error(
            "globalArguments.routing is required for pushRouting",
          );
        }
        const lines = routingLines(g);
        if (lines.length === 0) {
          throw new Error("globalArguments.routing produced no configuration");
        }
        return await applyConfig(
          context,
          "pushRouting",
          lines,
          args.dryRun,
          false,
        );
      },
    },
  },
  checks: {
    "switch-reachable": {
      description:
        "TCP-probe the switch SSH port before pushing configuration.",
      labels: ["live"],
      appliesTo: ["applyBaseline", "pushSnmp", "pushRouting"],
      execute: async (context: CheckContext): Promise<CheckResult> => {
        const { host, port, commandTimeoutMs } = context.globalArgs;
        const timeoutMs = Math.max(3000, Math.min(commandTimeoutMs, 10000));
        try {
          await probeTcp(host, port, timeoutMs);
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

/** Context passed to pre-flight checks (no data-writing surface). */
interface CheckContext {
  globalArgs: CiscoIosGlobalArgs;
}
/** Pre-flight check result. */
interface CheckResult {
  pass: boolean;
  errors?: string[];
}

/** Open a TCP connection within `timeoutMs`, closing it (or a late one) immediately. */
function probeTcp(
  hostname: string,
  port: number,
  timeoutMs: number,
): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      reject(new Error(`timed out after ${timeoutMs} ms`));
    }, timeoutMs);
    Deno.connect({ hostname, port }).then(
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
    warning: (msg: string, props?: Record<string, unknown>) => void;
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
): Promise<{ dataHandles: DataHandle[] }> {
  const g = context.globalArgs;
  context.logger.info(
    "Applying {method} to {host} ({count} lines, dryRun={dryRun})",
    {
      method,
      host: g.host,
      count: lines.length,
      dryRun,
    },
  );
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
        appliedAt: new Date().toISOString(),
      },
    );
    return { dataHandles: [handle] };
  }
  const result = await runIosSession(g, { configLines: lines, save: true });
  const err = findIosError(result.transcript);
  if (err) throw new Error(`${method} failed: ${err}`);
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
        : tail(result.transcript, 2000),
      appliedAt: new Date().toISOString(),
    },
  );
  context.logger.info("Applied {method} to {host} (saved=true)", {
    method,
    host: g.host,
  });
  return { dataHandles: [handle] };
}

// ---- private helpers ----

function output(
  execOutputs: { command: string; output: string }[],
  cmd: string,
): string {
  return execOutputs.find((e) => e.command === cmd)?.output ?? "";
}

function tail(s: string, n: number): string {
  return s.length <= n ? s : s.slice(s.length - n);
}
