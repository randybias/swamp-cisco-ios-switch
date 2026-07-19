# @dougschaefer/cisco-ios-switch

A [Swamp](https://swamp-club.com/) extension model for managing a Cisco IOS
switch (e.g. Catalyst 2960) **over SSH** after it has been bootstrapped at the
console. It drives the interactive VTY the way an operator would — disable the
pager, optionally enter enable mode, push config, and `write memory` — capturing
the transcript and parsing device facts.

## What it does and does not do

This model **owns the switch after SSH is reachable**. It does **not** factory
reset the switch and **cannot** bootstrap SSH itself: a freshly wiped switch has
no IP and no VTY, so the first management config (hostname, domain, RSA key,
management IP, `transport input ssh`, a privilege-15 user) must be entered over
the **console**. Once the switch answers on its management IP, this model takes
over.

## Methods

| Method             | Mutating | Description                                                                                                                                                             |
| ------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `getRunningConfig` | no       | Capture `show running-config` (secrets redacted by default) and `show version`; store the config file plus parsed model/IOS/uptime facts.                               |
| `runCommands`      | no       | Run validated single-line `show` commands and capture output with known secrets redacted by default.                                                                    |
| `applyBaseline`    | yes      | Assert idempotent secure-access hardening: hostname/domain, `service password-encryption`, HTTP off, console + VTY login/timeout, SSH-only transport. Saves to startup. |
| `pushSnmp`         | yes      | Configure SNMPv2c read-only/read-write communities, location, contact, and an optional trap host from `globalArguments.snmp`. Saves to startup.                         |
| `pushRouting`      | yes      | Apply Layer-3 intent from `globalArguments.routing`: `ip routing`, VLANs/SVIs, a static default route, and access-port assignments. Saves to startup.                   |

Every mutating method requires an explicit `dryRun` choice. Use `dryRun=true` to
render and store the exact IOS lines **without connecting**; use `dryRun=false`
only when the reviewed intent should be applied and saved.

## Pre-flight check

A `live`-labeled `switch-reachable` check TCP-probes the configured SSH port
before every method, failing fast if the switch is unreachable. Skip it for an
offline dry run with `--skip-check-label live`.

## Installation

Trust Doug Schaefer's collective, then pull the extension into an initialized
Swamp repository:

```bash
swamp extension trust add dougschaefer
swamp extension pull @dougschaefer/cisco-ios-switch
```

## Global arguments

| Key                       | Sensitive | Notes                                                                                              |
| ------------------------- | --------- | -------------------------------------------------------------------------------------------------- |
| `host`                    |           | Management IP or hostname                                                                          |
| `port`                    |           | Explicit SSH port, `1`–`65535`                                                                     |
| `username`                |           | A privilege-15 local user                                                                          |
| `password`                | yes       | `${{ vault.get(your-vault, <switch>-admin) }}`                                                     |
| `enableSecret`            | yes       | Set **only** if the login does not land in privilege 15                                            |
| `hostname` / `domainName` |           | Asserted by `applyBaseline`                                                                        |
| `hostKeyPolicy`           |           | Required: `strict` verifies known hosts; `insecure` is an explicit compatibility opt-out           |
| `legacyAlgorithms`        |           | Required boolean: append legacy SSH kex/cipher/host-key algorithms only when the target needs them |
| `commandTimeoutMs`        |           | Explicit connect/session budget, `1000`–`300000` milliseconds                                      |
| `snmp`                    | partial   | `readOnly`/`readWrite` (sensitive), `location`, `contact`, `trapHost`                              |
| `routing`                 |           | `enabled`, `defaultRouteNextHop`, `vlans[]`, `accessPorts[]`                                       |

### Example definition

```yaml
type: "@dougschaefer/cisco-ios-switch"
globalArguments:
  host: 192.0.2.10
  port: 22
  username: automation
  password: ${{ vault.get(your-vault, switch-test-password) }}
  hostname: switch-test-1
  domainName: example.test
  hostKeyPolicy: strict
  legacyAlgorithms: true
  commandTimeoutMs: 20000
  snmp:
    readOnly: ${{ vault.get(your-vault, switch-test-snmp-ro) }}
    readWrite: ${{ vault.get(your-vault, switch-test-snmp-rw) }}
    location: Test Lab
    contact: noc@example.test
    trapHost: 192.0.2.50
  routing:
    enabled: true
    defaultRouteNextHop: 192.0.2.1
    vlans:
      - { id: 20, name: USER }
      - { id: 30, name: AV }
    accessPorts:
      - {
          range: "gigabitEthernet 1/0/1 - 12",
          vlanId: 20,
          description: User Ports,
          portfast: true,
        }
      - {
          range: "gigabitEthernet 1/0/13 - 24",
          vlanId: 30,
          description: AV Ports,
          portfast: true,
        }
```

## Usage

```bash
# Create one definition per switch (or commit it as YAML — see above).
swamp model create "@dougschaefer/cisco-ios-switch" switch-test-1 \
  --global-arg host=192.0.2.10 \
  --global-arg port=22 \
  --global-arg username=automation \
  --global-arg password='${{ vault.get(your-vault, switch-test-password) }}' \
  --global-arg hostname=switch-test-1 \
  --global-arg domainName=example.test \
  --global-arg hostKeyPolicy=strict \
  --global-arg legacyAlgorithms=true \
  --global-arg commandTimeoutMs=20000

# Review what would change without touching the switch (skip the live probe).
swamp model method run switch-test-1 applyBaseline --input dryRun=true --skip-check-label live

# Apply for real (the live reachability check runs first).
swamp model method run switch-test-1 applyBaseline --input dryRun=false

# Verify, then capture a redacted running-config.
swamp model method run switch-test-1 runCommands --input 'commands=["show ip ssh","show ip route"]'
swamp model method run switch-test-1 getRunningConfig
```

For a definition that includes the `snmp` and `routing` intent from the YAML
example, the corresponding mutation methods are:

```bash
swamp model method run switch-test-1 pushSnmp    --input dryRun=false
swamp model method run switch-test-1 pushRouting --input dryRun=false
```

## Transport notes

- Shells out to the system `ssh` client (OpenSSH ≥ 8.4) rather than bundling a
  JS SSH library — swamp bundles extensions with `deno bundle`, which can't
  resolve `ssh2`'s optional native addons. The login password is handed to `ssh`
  through a 0600 askpass helper, never on the command line.
- `hostKeyPolicy: strict` passes `StrictHostKeyChecking=yes` and uses the
  runner's trusted `known_hosts`. `insecure` disables verification only when
  explicitly selected.
- `legacyAlgorithms: true` appends legacy SHA-1 key exchange, `ssh-rsa`, CBC
  ciphers, and legacy MACs for old IOS images. It appends to—rather than
  replacing—modern algorithms.
- When `enableSecret` is configured, the driver waits for the IOS `Password:`
  prompt before sending it and verifies that the prompt changes to privileged
  `#` mode. Configuration is validated in one session and saved in a second
  session only after IOS returns no rejection; `[OK]` is required before a
  result is recorded as saved.

## Security

- All credentials (`password`, `enableSecret`, SNMP communities) are
  vault-resolved and marked sensitive.
- `getRunningConfig` redacts community/secret/password/key lines by default
  (`redactSecrets=false` to keep them). `pushSnmp` stores redacted lines and
  suppresses device output.
- `runCommands` rejects non-show commands, control characters, command chaining,
  and device-storage redirection (`>`, `| tee`, `| redirect`, and `| append`).
  Text and structured JSON output are redacted by default; raw output requires
  the explicit `redactSecrets=false` input. SSH login and enable credentials
  remain scrubbed from transport transcripts even with that opt-out.
- Generated configuration fields reject embedded control characters, and
  routing/SNMP schemas reject inconsistent or unsafe intent before SSH opens.

## Upgrade behavior

Version `2026.07.19.1` makes transport policy and nested routing behavior
explicit for new definitions. Existing published definitions migrate lazily with
their prior effective behavior preserved: port `22`, insecure host-key handling,
legacy algorithms enabled, a 20-second budget, and the prior nested routing
defaults. Update those migrated definitions to `hostKeyPolicy: strict` and
disable legacy algorithms wherever the target supports modern SSH.

Existing workflows and callers must also make two explicit migrations:

- Pass `dryRun=true` or `dryRun=false` to every mutating method.
- Restrict `runCommands` input to single-line `show` commands. Captured output
  is now redacted by default; use `redactSecrets=false` only when raw output is
  deliberately required and can be stored safely.

## Test

The offline suite covers schema injection defenses, upgrade behavior, config
generation, broad secret redaction, OpenSSH argv and lifecycle handling,
interactive transcript slicing, model entrypoints, dry-run/live mutation paths,
pre-flight checks, and failure classification:

```bash
deno test --allow-read --allow-write cisco-ios-switch/switch_test.ts
```

## License

MIT — see [LICENSE.txt](LICENSE.txt).
