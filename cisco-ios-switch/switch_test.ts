import {
  assert,
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@swamp-club/swamp-testing@0.20260706.24";
import {
  baselineLines,
  parseShowVersion,
  redactCommandOutput,
  redactConfig,
  routingLines,
  snmpLines,
} from "./_config.ts";
import {
  buildSshArgs,
  type CiscoIosGlobalArgs,
  CiscoIosGlobalArgsSchema,
  findIosError,
  type IosSpawn,
  runIosSession,
} from "./_ssh.ts";
import {
  createCiscoIosModel,
  model,
  probeTcp,
  upgradeGlobalArguments,
} from "./switch.ts";

const showVersion = [
  "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)",
  "switch-test-1 uptime is 12 weeks, 3 days, 4 hours, 5 minutes",
  "System returned to ROM by power-on",
  "Model number                     : WS-C2960-24TT-L",
].join("\n");

const runningConfig = [
  "hostname switch-test-1",
  "enable secret 5 synthetic-enable-hash",
  "username automation privilege 15 secret 5 synthetic-user-hash",
  "snmp-server community synthetic-community RO",
  "interface Vlan1",
  " ip address 192.0.2.10 255.255.255.0",
].join("\n");

const globalArgs = CiscoIosGlobalArgsSchema.parse({
  host: "switch.example.test",
  port: 22,
  username: "automation",
  password: "synthetic-password",
  hostname: "switch-test-1",
  domainName: "example.test",
  hostKeyPolicy: "strict",
  legacyAlgorithms: false,
  commandTimeoutMs: 20_000,
}) as CiscoIosGlobalArgs & { host: string; username: string; password: string };

/** Build validated global args for line-generator and model tests. */
function args(partial: Partial<CiscoIosGlobalArgs>): CiscoIosGlobalArgs {
  return CiscoIosGlobalArgsSchema.parse({ ...globalArgs, ...partial });
}

function commandOutput(
  stdout: string,
  stderr = "",
  code = 0,
): Deno.CommandOutput {
  return {
    success: code === 0,
    code,
    signal: null,
    stdout: new TextEncoder().encode(stdout),
    stderr: new TextEncoder().encode(stderr),
  };
}

function fakeSpawn(
  output: Deno.CommandOutput,
  capture: {
    command?: string;
    options?: Deno.CommandOptions;
    stdin?: string;
    askpassScript?: string;
    passwordFile?: string;
    stdinClosedBeforeOutput?: boolean;
  },
): IosSpawn {
  return (command, options) => {
    capture.command = command;
    capture.options = options;
    const askpass = options.env?.SSH_ASKPASS;
    if (askpass) capture.askpassScript = Deno.readTextFileSync(askpass);
    capture.passwordFile = options.env?.SWAMP_ASKPASS_PASSWORD_FILE;
    const chunks: Uint8Array[] = [];
    let closed = false;
    return {
      stdin: new WritableStream<Uint8Array>({
        write(chunk) {
          chunks.push(chunk.slice());
          capture.stdin = chunks.map((part) => new TextDecoder().decode(part))
            .join("");
        },
        close() {
          closed = true;
        },
      }),
      stdout: byteStream(output.stdout),
      stderr: byteStream(output.stderr),
      get status() {
        capture.stdinClosedBeforeOutput = closed;
        return Promise.resolve({
          success: output.success,
          code: output.code,
          signal: output.signal,
        });
      },
    };
  };
}

function byteStream(value: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      if (value.length > 0) controller.enqueue(value);
      controller.close();
    },
  });
}

function successfulTranscript(command = "show clock", output = "09:30:00 UTC") {
  return [
    "switch-test-1#terminal length 0",
    "switch-test-1#terminal width 0",
    `switch-test-1#${command}`,
    output,
    "switch-test-1#exit",
    "",
  ].join("\n");
}

Deno.test("global schema accepts explicit secure transport facts", () => {
  assertEquals(globalArgs.hostKeyPolicy, "strict");
  assertEquals(globalArgs.legacyAlgorithms, false);
  assertEquals(globalArgs.port, 22);
  assertEquals(globalArgs.commandTimeoutMs, 20_000);
  assertEquals(CiscoIosGlobalArgsSchema.shape.password.meta()?.sensitive, true);
  assertEquals(
    CiscoIosGlobalArgsSchema.shape.enableSecret.meta()?.sensitive,
    true,
  );
  const snmpSchema = CiscoIosGlobalArgsSchema.shape.snmp.unwrap();
  assertEquals(snmpSchema.shape.readOnly.meta()?.sensitive, true);
  assertEquals(snmpSchema.shape.readWrite.meta()?.sensitive, true);
});

Deno.test("global arguments validate as fully empty (bare fleet instance)", () => {
  const parsed = CiscoIosGlobalArgsSchema.parse({});
  assertEquals(parsed.port, 22);
  assertEquals(parsed.commandTimeoutMs, 20_000);
  assertEquals(parsed.hostKeyPolicy, "insecure");
  assertEquals(parsed.legacyAlgorithms, true);
  assertEquals(parsed.host, undefined);
});

Deno.test("getRunningConfig rejects a bare instance with no host/username/password", async () => {
  const testModel = createCiscoIosModel();
  const harness = createModelTestContext({
    globalArgs: CiscoIosGlobalArgsSchema.parse({}),
    methodName: "getRunningConfig",
  });
  await assertRejects(
    () =>
      testModel.methods.getRunningConfig.execute(
        testModel.methods.getRunningConfig.arguments.parse({}),
        harness.context as never,
      ),
    Error,
    "no host/username/password",
  );
});

Deno.test("global schema rejects malformed targets, credentials, and timeouts", () => {
  for (
    const overrides of [
      { host: "-oProxyCommand=synthetic" },
      { host: "host name" },
      { username: "automation@unexpected" },
      { password: "synthetic\nshow running-config" },
      { enableSecret: "synthetic\nconfigure terminal" },
      { hostname: "switch\nreload" },
      { domainName: "bad domain.example" },
      { port: 0 },
      { port: 65_536 },
      { commandTimeoutMs: 999 },
      { commandTimeoutMs: 300_001 },
    ]
  ) {
    assertEquals(
      CiscoIosGlobalArgsSchema.safeParse({ ...globalArgs, ...overrides })
        .success,
      false,
    );
  }
});

Deno.test("nested configuration schemas reject command injection and inconsistent intent", () => {
  const variants = [
    { snmp: { readOnly: "community with spaces" } },
    { snmp: { readOnly: "community\u001bescape" } },
    { snmp: { readWrite: "community\u0000null" } },
    { snmp: { readOnly: "safe", contact: "noc@example.test\nreload" } },
    { snmp: { readWrite: "safe", trapHost: "192.0.2.50" } },
    {
      routing: {
        enabled: true,
        vlans: [{ id: 20, name: "USER", sviIp: "192.0.2.1" }],
        accessPorts: [],
      },
    },
    {
      routing: {
        enabled: true,
        vlans: [{
          id: 20,
          name: "USER",
          sviIp: "192.0.2.1",
          sviMask: "255.0.255.0",
        }],
        accessPorts: [],
      },
    },
    {
      routing: {
        enabled: true,
        vlans: [{ id: 20, name: "USER\nreload" }],
        accessPorts: [],
      },
    },
    {
      routing: {
        enabled: true,
        vlans: [{ id: 20, name: "USER" }],
        accessPorts: [{
          range: "gigabitEthernet 1/0/1\nreload",
          vlanId: 20,
          description: "Users",
          portfast: true,
        }],
      },
    },
    {
      routing: {
        enabled: false,
        defaultRouteNextHop: "192.0.2.1",
        vlans: [],
        accessPorts: [],
      },
    },
    {
      routing: {
        enabled: true,
        vlans: [{ id: 20, name: "USER" }, { id: 20, name: "DUPLICATE" }],
        accessPorts: [],
      },
    },
  ];
  for (const variant of variants) {
    assertEquals(
      CiscoIosGlobalArgsSchema.safeParse({ ...globalArgs, ...variant }).success,
      false,
    );
  }
});

Deno.test("published-definition upgrade preserves old behavior and fills nested defaults", () => {
  const upgraded = upgradeGlobalArguments({
    host: "switch.example.test",
    username: "automation",
    password: "synthetic-password",
    snmp: {
      readWrite: "synthetic-rw",
      trapHost: "192.0.2.50",
    },
    routing: {
      defaultRouteNextHop: "192.0.2.1",
      accessPorts: [{
        range: "gigabitEthernet 1/0/1",
        vlanId: 20,
      }],
      vlans: [{ id: 20, name: "USER", sviIp: "192.0.2.1" }],
    },
  });
  assertEquals(upgraded.port, 22);
  assertEquals(upgraded.hostKeyPolicy, "insecure");
  assertEquals(upgraded.legacyAlgorithms, true);
  assertEquals(upgraded.commandTimeoutMs, 20_000);
  assertEquals(upgraded.snmp, { readWrite: "synthetic-rw" });
  assert(CiscoIosGlobalArgsSchema.safeParse(upgraded).success);
  const routing = upgraded.routing as Record<string, unknown>;
  assertEquals(routing.enabled, false);
  assertEquals(routing.defaultRouteNextHop, undefined);
  assertEquals(routing.vlans, [{ id: 20, name: "USER" }]);
  assertEquals(routing.accessPorts, [{
    range: "gigabitEthernet 1/0/1",
    vlanId: 20,
    description: "",
    portfast: true,
  }]);
  CiscoIosGlobalArgsSchema.parse(upgraded);
  assertEquals(model.upgrades.at(-1)?.toVersion, model.version);
});

Deno.test("baselineLines includes hostname/domain when set and SSH-only VTY", () => {
  const lines = baselineLines(args({
    hostname: "switch-test-1",
    domainName: "example.test",
  }));
  assert(lines.includes("hostname switch-test-1"));
  assert(lines.includes("ip domain-name example.test"));
  assert(lines.includes(" transport input ssh"));
  assert(lines.includes(" login local"));
  assert(lines.includes("no ip http server"));
});

Deno.test("baselineLines omits hostname/domain when unset", () => {
  const lines = baselineLines(
    args({ hostname: undefined, domainName: undefined }),
  );
  assert(!lines.some((line) => line.startsWith("hostname ")));
  assert(!lines.some((line) => line.startsWith("ip domain-name ")));
  assert(lines.includes("service password-encryption"));
});

Deno.test("snmpLines emits validated RO/RW identity and trap intent", () => {
  const lines = snmpLines(args({
    snmp: {
      readOnly: "synthetic-ro",
      readWrite: "synthetic-rw",
      location: "Test Lab",
      contact: "noc@example.test",
      trapHost: "192.0.2.50",
    },
  }));
  assertEquals(lines, [
    "snmp-server community synthetic-ro RO",
    "snmp-server community synthetic-rw RW",
    "snmp-server location Test Lab",
    "snmp-server contact noc@example.test",
    "snmp-server host 192.0.2.50 version 2c synthetic-ro",
    "snmp-server enable traps",
  ]);
});

Deno.test("routingLines builds VLANs, SVI, route, and access ports", () => {
  const lines = routingLines(args({
    routing: {
      enabled: true,
      defaultRouteNextHop: "192.0.2.1",
      vlans: [
        {
          id: 20,
          name: "USER",
          sviIp: "198.51.100.1",
          sviMask: "255.255.255.0",
        },
        { id: 30, name: "AV" },
      ],
      accessPorts: [{
        range: "gigabitEthernet 1/0/1 - 12",
        vlanId: 20,
        description: "Users",
        portfast: true,
      }],
    },
  }));
  assertEquals(lines[0], "ip routing");
  assert(lines.includes("interface vlan 20"));
  assert(lines.includes(" ip address 198.51.100.1 255.255.255.0"));
  assert(lines.includes("vlan 30"));
  assert(!lines.includes("interface vlan 30"));
  assert(lines.includes("ip route 0.0.0.0 0.0.0.0 192.0.2.1"));
  assert(lines.includes("interface range gigabitEthernet 1/0/1 - 12"));
  assert(lines.includes(" switchport access vlan 20"));
  assert(lines.includes(" spanning-tree portfast"));
});

Deno.test("routingLines supports explicit L2-only intent without portfast", () => {
  const lines = routingLines(args({
    routing: {
      enabled: false,
      vlans: [{ id: 40, name: "MGMT" }],
      accessPorts: [{
        range: "fastEthernet 0/1",
        vlanId: 40,
        description: "",
        portfast: false,
      }],
    },
  }));
  assert(!lines.includes("ip routing"));
  assert(!lines.some((line) => line.startsWith("ip route ")));
  assert(!lines.includes(" spanning-tree portfast"));
});

Deno.test("redactConfig covers IOS credentials across SNMP, AAA, routing, and NTP", () => {
  const raw = [
    runningConfig,
    "snmp-server host 192.0.2.50 version 2c synthetic-trap-community",
    "snmp-server host 192.0.2.51 traps version 2c synthetic-traps-community",
    "snmp-server host 192.0.2.52 informs synthetic-legacy-community",
    "snmp-server user monitor operators auth sha synthetic-auth priv aes 128 synthetic-priv",
    "radius-server host radius.example.test key 7 synthetic-radius",
    "server-private 192.0.2.60 auth-port 1812 acct-port 1813 key 7 synthetic-server-private",
    "ip ospf message-digest-key 1 md5 7 synthetic-ospf",
    "ntp authentication-key 4 md5 synthetic-ntp",
    "crypto isakmp key synthetic-isakmp address 192.0.2.80",
    " pre-shared-key address 192.0.2.81 key synthetic-keyring",
    "neighbor 192.0.2.70 password 7 synthetic-bgp",
    " key-string 7 synthetic-key-chain",
  ].join("\n");
  const redacted = redactConfig(raw);
  for (
    const secret of [
      "synthetic-enable-hash",
      "synthetic-user-hash",
      "synthetic-community",
      "synthetic-trap-community",
      "synthetic-traps-community",
      "synthetic-legacy-community",
      "synthetic-auth",
      "synthetic-priv",
      "synthetic-radius",
      "synthetic-server-private",
      "synthetic-ospf",
      "synthetic-ntp",
      "synthetic-isakmp",
      "synthetic-keyring",
      "synthetic-bgp",
      "synthetic-key-chain",
    ]
  ) {
    assert(!redacted.includes(secret));
  }
  assert(redacted.includes("hostname switch-test-1"));
});

Deno.test("redactCommandOutput preserves JSON structure", () => {
  const redacted = JSON.parse(redactCommandOutput(JSON.stringify({
    username: "automation",
    password: "synthetic-password",
    nested: {
      api_token: "synthetic-token",
      key: "synthetic-generic-key",
      config: "enable secret 5 synthetic-hash",
    },
  })));
  assertEquals(redacted.username, "automation");
  assertEquals(redacted.password, "<redacted>");
  assertEquals(redacted.nested.api_token, "<redacted>");
  assertEquals(redacted.nested.key, "<redacted>");
  assertEquals(redacted.nested.config, "enable secret <redacted>");
  assertEquals(
    JSON.parse(redactCommandOutput('[{"secret":"synthetic-array"}]')),
    [{ secret: "<redacted>" }],
  );
});

Deno.test("parseShowVersion extracts facts and normalizes missing fields", () => {
  assertEquals(parseShowVersion(showVersion), {
    hostname: "switch-test-1",
    model: "WS-C2960-24TT-L",
    iosVersion: "15.0(2)SE11",
    uptime: "12 weeks, 3 days, 4 hours, 5 minutes",
  });
  assertEquals(parseShowVersion("unrecognized"), {
    hostname: "",
    model: "",
    iosVersion: "",
    uptime: "",
  });
  assertEquals(
    parseShowVersion(
      "Cisco IOS XE Software, Version 17.09.04a\nedge-1 uptime is 2 days\nModel Number : C9300-24T",
    ),
    {
      hostname: "edge-1",
      model: "C9300-24T",
      iosVersion: "17.09.04a",
      uptime: "2 days",
    },
  );
  assertEquals(
    parseShowVersion(
      "Cisco IOS Software, C1000 Software, Version 15.2(7)E10\naccess-1 uptime is 3 weeks\nModel number : C1000-24T-4G-L",
    ).model,
    "C1000-24T-4G-L",
  );
});

Deno.test("findIosError catches rejections but not syslog", () => {
  assertEquals(
    findIosError("% Invalid input detected at '^' marker."),
    "% Invalid input detected at '^' marker.",
  );
  assert(findIosError("% Incomplete command.") !== null);
  assert(findIosError("% Authorization failed") !== null);
  assert(findIosError("% VLAN 999 does not exist") !== null);
  assert(findIosError("% Access denied") !== null);
  assertEquals(
    findIosError("%SYS-5-CONFIG_I: Configured from console by vty0"),
    null,
  );
});

Deno.test("read-only output may contain non-error percent-prefixed text", async () => {
  const transcript = successfulTranscript(
    "show running-config",
    "% Authorized operators only\nhostname switch-test-1",
  );
  const result = await runIosSession(
    globalArgs,
    { execCommands: ["show running-config"] },
    fakeSpawn(commandOutput(transcript), {}),
  );
  assert(result.execOutputs[0].output.includes("% Authorized operators only"));
});

Deno.test("transport always scrubs login secrets but leaves device redaction to the method", async () => {
  const sessionArgs = args({ snmp: { readOnly: "synthetic-community" } });
  const transcript = successfulTranscript(
    "show running-config",
    [
      "snmp-server community synthetic-community RO",
      `banner motd ${globalArgs.password}`,
    ].join("\n"),
  );
  const result = await runIosSession(
    sessionArgs,
    { execCommands: ["show running-config"] },
    fakeSpawn(commandOutput(transcript), {}),
  );
  assert(result.execOutputs[0].output.includes("synthetic-community"));
  assert(!result.execOutputs[0].output.includes(globalArgs.password));
});

Deno.test("runCommands accepts trimmed show commands and rejects mutation/chaining", () => {
  const parsed = model.methods.runCommands.arguments.parse({
    commands: [" show version ", "SHOW ip route"],
  });
  assertEquals(parsed.commands, ["show version", "SHOW ip route"]);
  assertEquals(parsed.redactSecrets, true);
  for (
    const command of [
      "configure terminal",
      "reload",
      "write erase",
      "show clock; reload",
      "show clock\nreload",
      "show clock\treload",
      "show running-config > flash:capture",
      "show running-config >> flash:capture",
      "show running-config | tee flash:capture",
      "show running-config | redirect flash:capture",
      "show running-config | append flash:capture",
    ]
  ) {
    assertThrows(
      () => model.methods.runCommands.arguments.parse({ commands: [command] }),
      Error,
      "single read-only show command",
    );
  }
});

Deno.test("mutating methods require an explicit dry-run choice", () => {
  for (const method of ["applyBaseline", "pushSnmp", "pushRouting"] as const) {
    assertThrows(() => model.methods[method].arguments.parse({}));
    assertEquals(model.methods[method].arguments.parse({ dryRun: true }), {
      dryRun: true,
    });
  }
});

Deno.test("strict SSH argv keeps host verification enabled and secrets absent", () => {
  const sshArgs = buildSshArgs(globalArgs, 20);
  assert(sshArgs.includes("StrictHostKeyChecking=yes"));
  assert(!sshArgs.includes("StrictHostKeyChecking=no"));
  assert(!sshArgs.includes("UserKnownHostsFile=/dev/null"));
  assert(!JSON.stringify(sshArgs).includes(globalArgs.password));
  assertEquals(sshArgs.at(-2), "--");
  assertEquals(sshArgs.at(-1), "automation@switch.example.test");
});

Deno.test("insecure and legacy transport choices are explicit", () => {
  const sshArgs = buildSshArgs(
    args({
      hostKeyPolicy: "insecure",
      legacyAlgorithms: true,
    }),
    20,
  );
  assert(sshArgs.includes("StrictHostKeyChecking=no"));
  assert(sshArgs.includes("UserKnownHostsFile=/dev/null"));
  assert(sshArgs.some((value) => value.startsWith("KexAlgorithms=+")));
  assert(sshArgs.includes("HostKeyAlgorithms=+ssh-rsa"));
});

Deno.test("SSH session keeps stdin open until IOS exits and captures output", async () => {
  const capture: Parameters<typeof fakeSpawn>[1] = {};
  const result = await runIosSession(
    globalArgs,
    { execCommands: ["show clock"] },
    fakeSpawn(commandOutput(successfulTranscript()), capture),
  );
  assertEquals(capture.command, "ssh");
  assertEquals(capture.stdinClosedBeforeOutput, false);
  assertEquals(
    capture.stdin,
    [
      "terminal length 0",
      "terminal width 0",
      "show clock",
      "exit",
      "",
    ].join("\n"),
  );
  assertEquals(
    capture.askpassScript,
    '#!/bin/sh\ncat "$SWAMP_ASKPASS_PASSWORD_FILE"\n',
  );
  assert(!JSON.stringify(capture.options?.args).includes(globalArgs.password));
  assert(!JSON.stringify(capture.options?.env).includes(globalArgs.password));
  assertEquals(result.execOutputs, [{
    command: "show clock",
    output: "09:30:00 UTC",
  }]);
  await assertRejects(() => Deno.stat(capture.passwordFile!));
});

Deno.test("SSH session sends enable secret only through the encrypted VTY stdin", async () => {
  const capture: Parameters<typeof fakeSpawn>[1] = {};
  const enabledArgs = args({ enableSecret: "synthetic-enable" });
  const responseAfterElevation = [
    "switch-test-1#terminal length 0",
    "switch-test-1#terminal width 0",
    "switch-test-1#show clock",
    "09:30:00 UTC",
    "switch-test-1#exit",
    "",
  ].join("\n");
  const writes: string[] = [];
  const interactiveSpawn: IosSpawn = (_command, options) => {
    capture.options = options;
    let stdoutController: ReadableStreamDefaultController<Uint8Array>;
    const stdout = new ReadableStream<Uint8Array>({
      start(controller) {
        stdoutController = controller;
        controller.enqueue(new TextEncoder().encode("switch-test-1>"));
      },
    });
    return {
      stdin: new WritableStream<Uint8Array>({
        write(chunk) {
          const text = new TextDecoder().decode(chunk);
          writes.push(text);
          capture.stdin = writes.join("");
          if (text === "enable\n") {
            stdoutController.enqueue(new TextEncoder().encode("\nPassword:"));
          } else if (text === "synthetic-enable\n") {
            stdoutController.enqueue(
              new TextEncoder().encode("\nswitch-test-1#"),
            );
          } else {
            stdoutController.enqueue(
              new TextEncoder().encode(`\n${responseAfterElevation}`),
            );
            stdoutController.close();
          }
        },
      }),
      stdout,
      stderr: byteStream(new Uint8Array()),
      status: Promise.resolve({ success: true, code: 0, signal: null }),
    };
  };
  const result = await runIosSession(
    enabledArgs,
    { execCommands: ["show clock"] },
    interactiveSpawn,
  );
  assertEquals(writes[0], "enable\n");
  assertEquals(writes[1], "synthetic-enable\n");
  assert(writes[2].startsWith("terminal length 0\n"));
  assert(!result.transcript.includes("synthetic-enable"));
  assert(!JSON.stringify(capture.options?.args).includes("synthetic-enable"));
  assert(!JSON.stringify(capture.options?.env).includes("synthetic-enable"));
});

Deno.test("SSH session renders configuration without pre-buffering save", async () => {
  const capture: Parameters<typeof fakeSpawn>[1] = {};
  const transcript = [
    "switch-test-1#terminal length 0",
    "switch-test-1#terminal width 0",
    "switch-test-1#configure terminal",
    "switch-test-1(config)#hostname switch-test-2",
    "switch-test-2(config)#end",
    "switch-test-2#exit",
    "",
  ].join("\n");
  await runIosSession(
    globalArgs,
    { configLines: ["hostname switch-test-2"] },
    fakeSpawn(commandOutput(transcript), capture),
  );
  assertEquals(
    capture.stdin,
    [
      "terminal length 0",
      "terminal width 0",
      "configure terminal",
      "hostname switch-test-2",
      "end",
      "exit",
      "",
    ].join("\n"),
  );
});

Deno.test("SSH session rejects empty success and authentication stderr", async () => {
  await assertRejects(
    () =>
      runIosSession(
        globalArgs,
        { execCommands: ["show clock"] },
        fakeSpawn(commandOutput(""), {}),
      ),
    Error,
    "produced no session",
  );
  await assertRejects(
    () =>
      runIosSession(
        globalArgs,
        { execCommands: ["show clock"] },
        fakeSpawn(
          commandOutput(successfulTranscript(), "Permission denied"),
          {},
        ),
      ),
    Error,
    "authentication failed",
  );
});

Deno.test("SSH session represents a command whose echo is absent as empty output", async () => {
  const transcript = [
    "switch-test-1#terminal length 0",
    "switch-test-1#terminal width 0",
    "switch-test-1#exit",
    "",
  ].join("\n");
  const result = await runIosSession(
    globalArgs,
    { execCommands: ["show clock"] },
    fakeSpawn(commandOutput(transcript), {}),
  );
  assertEquals(result.execOutputs, [{ command: "show clock", output: "" }]);
});

Deno.test("SSH session rejects a nonzero exit even with partial stdout", async () => {
  await assertRejects(
    () =>
      runIosSession(
        globalArgs,
        { execCommands: ["show clock"] },
        fakeSpawn(
          commandOutput(successfulTranscript(), "connection reset", 255),
          {},
        ),
      ),
    Error,
    "exited with code 255",
  );
});

for (
  const [stderr, expected] of [
    ["Permission denied", "authentication failed"],
    ["Connection refused", "connection refused"],
    ["Connection timed out", "connection timed out"],
    ["no matching key exchange method found", "algorithm negotiation failed"],
    ["Could not resolve hostname test", "host could not be resolved"],
    ["unexpected ssh failure", "unexpected ssh failure"],
  ] as const
) {
  Deno.test(`SSH session classifies failure: ${expected}`, async () => {
    await assertRejects(
      () =>
        runIosSession(
          globalArgs,
          { execCommands: ["show clock"] },
          fakeSpawn(commandOutput("", stderr, 255), {}),
        ),
      Error,
      expected,
    );
  });
}

Deno.test("SSH failure classification never includes raw or overlapping secrets", async () => {
  const negotiation = await assertRejects(
    () =>
      runIosSession(
        globalArgs,
        { execCommands: ["show clock"] },
        fakeSpawn(
          commandOutput(
            "",
            `no matching key exchange method found: ${globalArgs.password}`,
            255,
          ),
          {},
        ),
      ),
    Error,
    "algorithm negotiation failed",
  );
  assert(!negotiation.message.includes(globalArgs.password));

  const overlappingArgs = args({
    password: "synthetic",
    enableSecret: "synthetic-enable",
  });
  const overlapping = await assertRejects(
    () =>
      runIosSession(overlappingArgs, { execCommands: ["show clock"] }, () => {
        throw new Error("failure synthetic-enable");
      }),
    Error,
    "failure ***",
  );
  assert(!overlapping.message.includes("synthetic-enable"));
  assert(!overlapping.message.includes("***-enable"));
});

Deno.test("SSH session rejects IOS command errors returned with exit zero", async () => {
  const transcript = successfulTranscript(
    "show unsupported",
    "% Invalid input detected at '^' marker.",
  );
  await assertRejects(
    () =>
      runIosSession(
        globalArgs,
        { execCommands: ["show unsupported"] },
        fakeSpawn(commandOutput(transcript), {}),
      ),
    Error,
    "IOS rejected a command",
  );
});

Deno.test("SSH session normalizes and redacts spawn failures", async () => {
  const error = await assertRejects(
    () =>
      runIosSession(globalArgs, { execCommands: ["show clock"] }, () => {
        throw `spawn failed with ${globalArgs.password}`;
      }),
    Error,
    "spawn failed with ***",
  );
  assert(!error.message.includes(globalArgs.password));
});

Deno.test("SSH session redacts writer failures and cleans temporary credentials", async () => {
  let passwordFile = "";
  const error = await assertRejects(
    () =>
      runIosSession(
        globalArgs,
        { execCommands: ["show clock"] },
        (_cmd, options) => {
          passwordFile = options.env?.SWAMP_ASKPASS_PASSWORD_FILE ?? "";
          return {
            stdin: new WritableStream<Uint8Array>({
              write() {
                throw new Error(`write failed with ${globalArgs.password}`);
              },
            }),
            stdout: byteStream(new Uint8Array()),
            stderr: byteStream(new Uint8Array()),
            status: Promise.resolve({ success: true, code: 0, signal: null }),
          };
        },
      ),
    Error,
    "write failed with ***",
  );
  assert(!error.message.includes(globalArgs.password));
  await assertRejects(() => Deno.stat(passwordFile));
});

Deno.test("getRunningConfig entrypoint writes redacted config and parsed status", async () => {
  let receivedPlan: Parameters<typeof runIosSession>[1] | undefined;
  const testModel = createCiscoIosModel({
    runSession: (_args, plan) => {
      receivedPlan = plan;
      return Promise.resolve({
        transcript: "synthetic transcript",
        execOutputs: [
          { command: "show version", output: showVersion },
          { command: "show running-config", output: runningConfig },
        ],
      });
    },
    now: () => new Date("2026-01-10T12:00:00.000Z"),
  });
  const harness = createModelTestContext({
    globalArgs,
    methodName: "getRunningConfig",
  });
  const methodArgs = testModel.methods.getRunningConfig.arguments.parse({});
  const result = await testModel.methods.getRunningConfig.execute(
    methodArgs,
    harness.context as never,
  );
  assertEquals(receivedPlan, {
    execCommands: ["show version", "show running-config"],
  });
  assertEquals(result.dataHandles.length, 2);
  const [status] = harness.getWrittenResources();
  assertEquals(status.name, "switch.example.test-status");
  assertEquals(status.data.hostname, "switch-test-1");
  assertEquals(status.data.model, "WS-C2960-24TT-L");
  assertEquals(status.data.capturedAt, "2026-01-10T12:00:00.000Z");
  const config = new TextDecoder().decode(harness.getWrittenFiles()[0].content);
  assert(config.includes("enable secret <redacted>"));
  assert(!config.includes("synthetic-enable-hash"));
});

Deno.test("getRunningConfig rejects missing requested output before writing", async () => {
  const testModel = createCiscoIosModel({
    runSession: () => Promise.resolve({ transcript: "", execOutputs: [] }),
  });
  const harness = createModelTestContext({
    globalArgs,
    methodName: "getRunningConfig",
  });
  await assertRejects(
    () =>
      testModel.methods.getRunningConfig.execute(
        { redactSecrets: true },
        harness.context as never,
      ),
    Error,
    "returned no output",
  );
  assertEquals(harness.getWrittenResources(), []);
  assertEquals(harness.getWrittenFiles(), []);
});

Deno.test("runCommands entrypoint redacts by default and supports raw opt-out", async () => {
  const testModel = createCiscoIosModel({
    runSession: (_args, plan) =>
      Promise.resolve({
        transcript: "synthetic transcript",
        execOutputs: (plan.execCommands ?? []).map((command) => ({
          command,
          output: "username automation secret 5 synthetic-command-secret",
        })),
      }),
    now: () => new Date("2026-01-10T12:00:00.000Z"),
  });
  for (
    const [redactSecrets, expected] of [[true, "<redacted>"], [
      false,
      "synthetic-command-secret",
    ]] as const
  ) {
    const harness = createModelTestContext({
      globalArgs,
      methodName: "runCommands",
    });
    const methodArgs = testModel.methods.runCommands.arguments.parse({
      commands: [" show running-config "],
      redactSecrets,
    });
    await testModel.methods.runCommands.execute(
      methodArgs,
      harness.context as never,
    );
    const commands = harness.getWrittenResources()[0].data.commands as {
      command: string;
      output: string;
    }[];
    assertEquals(commands[0].command, "show running-config");
    assert(commands[0].output.includes(expected));
  }
});

Deno.test("applyBaseline dry run writes intent without opening SSH", async () => {
  let calls = 0;
  const testModel = createCiscoIosModel({
    runSession: () => {
      calls++;
      return Promise.reject(new Error("must not connect"));
    },
    now: () => new Date("2026-01-10T12:00:00.000Z"),
  });
  const harness = createModelTestContext({
    globalArgs,
    methodName: "applyBaseline",
  });
  await testModel.methods.applyBaseline.execute(
    { dryRun: true },
    harness.context as never,
  );
  assertEquals(calls, 0);
  const [resource] = harness.getWrittenResources();
  assertEquals(resource.name, "switch.example.test-applyBaseline");
  assertEquals(resource.data.dryRun, true);
  assertEquals(resource.data.saved, false);
  assertEquals(resource.data.appliedAt, "2026-01-10T12:00:00.000Z");
});

Deno.test("pushSnmp dry run stores only redacted communities", async () => {
  const snmpArgs = args({
    snmp: {
      readOnly: "synthetic-ro",
      readWrite: "synthetic-rw",
      location: "Test Lab",
    },
  });
  const testModel = createCiscoIosModel({
    runSession: () => Promise.reject(new Error("must not connect")),
  });
  const harness = createModelTestContext({
    globalArgs: snmpArgs,
    methodName: "pushSnmp",
  });
  await testModel.methods.pushSnmp.execute(
    { dryRun: true },
    harness.context as never,
  );
  const lines = harness.getWrittenResources()[0].data.appliedLines as string[];
  assert(lines.some((line) => line.includes("<redacted> RO")));
  assert(lines.some((line) => line.includes("<redacted> RW")));
  assert(!JSON.stringify(lines).includes("synthetic-ro"));
  assert(!JSON.stringify(lines).includes("synthetic-rw"));
});

Deno.test("pushRouting dry run renders validated routing intent", async () => {
  const routingArgs = args({
    routing: {
      enabled: false,
      vlans: [{ id: 20, name: "USER" }],
      accessPorts: [],
    },
  });
  const testModel = createCiscoIosModel();
  const harness = createModelTestContext({
    globalArgs: routingArgs,
    methodName: "pushRouting",
  });
  await testModel.methods.pushRouting.execute(
    { dryRun: true },
    harness.context as never,
  );
  const lines = harness.getWrittenResources()[0].data.appliedLines as string[];
  assert(lines.includes("vlan 20"));
});

Deno.test("live configuration applies and saves while redacting stored device output", async () => {
  const receivedPlans: Parameters<typeof runIosSession>[1][] = [];
  const testModel = createCiscoIosModel({
    runSession: (_args, plan) => {
      receivedPlans.push(plan);
      if (plan.execCommands?.includes("write memory")) {
        return Promise.resolve({
          transcript: "Building configuration...\n[OK]",
          execOutputs: [{
            command: "write memory",
            output: "Building configuration...\n[OK]",
          }],
        });
      }
      return Promise.resolve({
        transcript: "username automation secret 5 synthetic-device-secret",
        execOutputs: [],
      });
    },
  });
  const harness = createModelTestContext({
    globalArgs,
    methodName: "applyBaseline",
  });
  await testModel.methods.applyBaseline.execute(
    { dryRun: false },
    harness.context as never,
  );
  assertEquals(receivedPlans, [
    { configLines: baselineLines(globalArgs) },
    { execCommands: ["write memory"] },
  ]);
  const [resource] = harness.getWrittenResources();
  assertEquals(resource.data.saved, true);
  assertEquals(resource.data.dryRun, false);
  assert((resource.data.deviceOutput as string).includes("secret <redacted>"));
  assert(
    !(resource.data.deviceOutput as string).includes("synthetic-device-secret"),
  );
});

for (
  const [method, methodGlobalArgs, forbidden] of [
    [
      "pushSnmp",
      args({ snmp: { readOnly: "synthetic-live-ro" } }),
      "synthetic-live-ro",
    ],
    [
      "pushRouting",
      args({
        routing: {
          enabled: false,
          vlans: [{ id: 20, name: "USER" }],
          accessPorts: [],
        },
      }),
      "synthetic-password",
    ],
  ] as const
) {
  Deno.test(`${method} live path applies then verifies save without leaking secrets`, async () => {
    const plans: Parameters<typeof runIosSession>[1][] = [];
    const testModel = createCiscoIosModel({
      runSession: (_args, plan) => {
        plans.push(plan);
        if (plan.execCommands?.includes("write memory")) {
          return Promise.resolve({
            transcript: "Building configuration...\n[OK]",
            execOutputs: [{
              command: "write memory",
              output: "Building configuration...\n[OK]",
            }],
          });
        }
        return Promise.resolve({
          transcript: method === "pushRouting"
            ? `username automation password ${forbidden}`
            : `configuration accepted ${forbidden}`,
          execOutputs: [],
        });
      },
    });
    const harness = createModelTestContext({
      globalArgs: methodGlobalArgs,
      methodName: method,
    });
    if (method === "pushSnmp") {
      await testModel.methods.pushSnmp.execute(
        { dryRun: false },
        harness.context as never,
      );
    } else {
      await testModel.methods.pushRouting.execute(
        { dryRun: false },
        harness.context as never,
      );
    }
    assertEquals(plans.length, 2);
    assertEquals(plans[1], { execCommands: ["write memory"] });
    assert(
      !JSON.stringify(harness.getWrittenResources()).includes(forbidden),
    );
  });
}

Deno.test("live configuration requires a positive save acknowledgement", async () => {
  let calls = 0;
  const testModel = createCiscoIosModel({
    runSession: (_args, plan) => {
      calls++;
      return Promise.resolve({
        transcript: plan.configLines ? "configuration accepted" : "Done",
        execOutputs: plan.execCommands?.includes("write memory")
          ? [{ command: "write memory", output: "Done" }]
          : [],
      });
    },
  });
  const harness = createModelTestContext({
    globalArgs,
    methodName: "applyBaseline",
  });
  await assertRejects(
    () =>
      testModel.methods.applyBaseline.execute(
        { dryRun: false },
        harness.context as never,
      ),
    Error,
    "did not acknowledge [OK]",
  );
  assertEquals(calls, 2);
  assertEquals(harness.getWrittenResources(), []);
});

Deno.test("configuration entrypoints reject missing intent and IOS failures", async () => {
  let runnerCalls = 0;
  const testModel = createCiscoIosModel({
    runSession: () => {
      runnerCalls++;
      return Promise.resolve({
        transcript: "% Invalid input detected at '^' marker.",
        execOutputs: [],
      });
    },
  });
  const baselineHarness = createModelTestContext({
    globalArgs,
    methodName: "applyBaseline",
  });
  await assertRejects(
    () =>
      testModel.methods.applyBaseline.execute(
        { dryRun: false },
        baselineHarness.context as never,
      ),
    Error,
    "applyBaseline failed",
  );
  assertEquals(runnerCalls, 1);
  assertEquals(baselineHarness.getWrittenResources(), []);

  const missingSnmp = createModelTestContext({
    globalArgs,
    methodName: "pushSnmp",
  });
  await assertRejects(
    () =>
      testModel.methods.pushSnmp.execute(
        { dryRun: true },
        missingSnmp.context as never,
      ),
    Error,
    "must define at least one",
  );
  assertEquals(
    missingSnmp.getLogs()[0]?.message,
    "Preparing {method} for {host} (dryRun={dryRun})",
  );
  const missingRouting = createModelTestContext({
    globalArgs,
    methodName: "pushRouting",
  });
  await assertRejects(
    () =>
      testModel.methods.pushRouting.execute(
        { dryRun: true },
        missingRouting.context as never,
      ),
    Error,
    "routing is required",
  );
  assertEquals(
    missingRouting.getLogs()[0]?.message,
    "Preparing {method} for {host} (dryRun={dryRun})",
  );

  const emptyRoutingArgs = args({
    routing: { enabled: false, vlans: [], accessPorts: [] },
  });
  const emptyRouting = createModelTestContext({
    globalArgs: emptyRoutingArgs,
    methodName: "pushRouting",
  });
  await assertRejects(
    () =>
      testModel.methods.pushRouting.execute(
        { dryRun: true },
        emptyRouting.context as never,
      ),
    Error,
    "produced no configuration",
  );
});

const fleetTarget = {
  name: "sw-a",
  class: "cisco_ios_switch" as const,
  host: "sw-a.example.test",
  port: 22,
  username: "automation",
  password: "synthetic-password",
  hostKeyPolicy: "insecure" as const,
  legacyAlgorithms: true,
  commandTimeoutMs: 20_000,
};

Deno.test("discoverFleet captures version, config, and LLDP for every target in one execution", async () => {
  const testModel = createCiscoIosModel({
    probeTcp: () => Promise.resolve(),
    runSession: (_args, plan) =>
      Promise.resolve({
        transcript: "synthetic transcript",
        execOutputs: (plan.execCommands ?? []).map((command) => ({
          command,
          output: command === "show version"
            ? showVersion
            : command === "show running-config"
            ? runningConfig
            : "synthetic lldp output",
        })),
      }),
    now: () => new Date("2026-01-10T12:00:00.000Z"),
  });
  const harness = createModelTestContext({
    globalArgs: CiscoIosGlobalArgsSchema.parse({}),
    methodName: "discoverFleet",
  });
  const args = testModel.methods.discoverFleet.arguments.parse({
    targets: [fleetTarget],
  });

  const result = await testModel.methods.discoverFleet.execute(
    args,
    harness.context as never,
  );

  assertEquals(result.dataHandles.length, 4);
  const resources = harness.getWrittenResources();
  const summary = resources.find((r) => r.specName === "fleetSummary")!;
  assertEquals(summary.data.succeeded, 1);
  const status = resources.find((r) => r.specName === "status")!;
  assertEquals(status.name, "sw-a-status");
});

Deno.test("discoverFleet isolates one target's failure from the rest of the fleet", async () => {
  const failing = { ...fleetTarget, name: "sw-b", host: "sw-b.example.test" };
  const testModel = createCiscoIosModel({
    probeTcp: (host) =>
      host === failing.host
        ? Promise.reject(new Error("connection refused"))
        : Promise.resolve(),
    runSession: (_args, plan) =>
      Promise.resolve({
        transcript: "synthetic transcript",
        execOutputs: (plan.execCommands ?? []).map((command) => ({
          command,
          output: command === "show version" ? showVersion : runningConfig,
        })),
      }),
  });
  const harness = createModelTestContext({
    globalArgs: CiscoIosGlobalArgsSchema.parse({}),
    methodName: "discoverFleet",
  });
  const args = testModel.methods.discoverFleet.arguments.parse({
    targets: [fleetTarget, failing],
  });

  await testModel.methods.discoverFleet.execute(args, harness.context as never);

  const summary = harness.getWrittenResources().find((r) =>
    r.specName === "fleetSummary"
  )!;
  assertEquals(summary.data.total, 2);
  assertEquals(summary.data.succeeded, 1);
  assertEquals(summary.data.failed, 1);
});

Deno.test("discoverFleet rejects duplicate target names before execution", () => {
  assertThrows(() =>
    model.methods.discoverFleet.arguments.parse({
      targets: [fleetTarget, { ...fleetTarget, host: "other.example.test" }],
    })
  );
});

Deno.test("discoverFleet bounds one execution to 64 targets", () => {
  assertThrows(() =>
    model.methods.discoverFleet.arguments.parse({
      targets: Array.from({ length: 65 }, (_, i) => ({
        ...fleetTarget,
        name: `sw-${i}`,
      })),
    })
  );
});

Deno.test("switch-reachable check uses explicit configured port and bounded timeout", async () => {
  let probe: { host: string; port: number; timeoutMs: number } | undefined;
  const passingModel = createCiscoIosModel({
    probeTcp: (host, port, timeoutMs) => {
      probe = { host, port, timeoutMs };
      return Promise.resolve();
    },
  });
  const portArgs = args({ port: 2222, commandTimeoutMs: 30_000 });
  assertEquals(
    await passingModel.checks["switch-reachable"].execute({
      globalArgs: portArgs,
    }),
    { pass: true },
  );
  assertEquals(probe, {
    host: "switch.example.test",
    port: 2222,
    timeoutMs: 10_000,
  });
  const failingModel = createCiscoIosModel({
    probeTcp: () => Promise.reject(new Error("synthetic refusal")),
  });
  const failed = await failingModel.checks["switch-reachable"].execute({
    globalArgs: portArgs,
  });
  assertEquals(failed.pass, false);
  assert(failed.errors?.[0].includes("switch.example.test:2222"));
});

Deno.test("probeTcp closes successful and late connections and normalizes failures", async () => {
  let closed = false;
  await probeTcp("switch.example.test", 2222, 100, () =>
    Promise.resolve({
      close() {
        closed = true;
      },
    }));
  assert(closed);
  await assertRejects(
    () =>
      probeTcp(
        "switch.example.test",
        2222,
        100,
        () => Promise.reject("synthetic refusal"),
      ),
    Error,
    "synthetic refusal",
  );
  let resolveLate: ((connection: { close(): void }) => void) | undefined;
  let lateClosed = false;
  const late = probeTcp(
    "switch.example.test",
    2222,
    1,
    () =>
      new Promise((resolve) => {
        resolveLate = resolve;
      }),
  );
  await assertRejects(() => late, Error, "timed out after 1 ms");
  resolveLate?.({
    close() {
      lateClosed = true;
    },
  });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert(lateClosed);

  let rejectLate: ((error: unknown) => void) | undefined;
  const lateFailure = probeTcp(
    "switch.example.test",
    2222,
    1,
    () =>
      new Promise((_resolve, reject) => {
        rejectLate = reject;
      }),
  );
  await assertRejects(() => lateFailure, Error, "timed out after 1 ms");
  rejectLate?.(new Error("late refusal"));
  await new Promise((resolve) => setTimeout(resolve, 0));
});
