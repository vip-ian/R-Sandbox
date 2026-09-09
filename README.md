# R-Sandbox

**An AI agent that builds a project-specific sandbox, performs a security
preflight, and explains the evidence and uncertainty around untrusted research code.**

R-Sandbox accepts a local checkout of a research project (including a GitHub
clone) and a natural-language goal.
The agent understands the repository, infers the minimum authority needed for
that goal, builds an isolated environment, performs an explicit shadow
execution, collects bounded evidence about some attempted behavior, and
returns an evidence-backed security-gate result. The verdict model includes
**review**, **unsafe**,
**inconclusive**, and **safe**, but the bundled Docker backend can independently
produce only **review** or **inconclusive** today. **Unsafe** requires a trusted
independent-observer adapter, which is not bundled. **Safe** additionally
requires a typed, run-bound coverage attestation and environment-readiness
attestation, neither of which is implemented.

The sandbox is not the final product. It is the agent's enforcement and
measurement tool.

## What the agent does

~~~text
Observe -> Understand -> Plan -> Authorize -> Build
        -> Execute -> Monitor -> Reflect -> Re-plan -> Report
~~~

1. Inventories the bounded repository snapshot and parses README, Python,
   notebooks, `requirements.txt`, and `pyproject.toml` without importing or
   executing the project.
2. Relates file, network, process, environment, device, resource, and side
   effect requirements to the stated research goal.
3. Converts semantic proposals into a typed capability contract. A
   deterministic policy engine—not the language model—grants or denies them.
4. Withholds links and a conservative set of common credential-like paths in
   a bounded content-addressed
   snapshot, then builds a project-specific Docker sandbox with that snapshot read-only, a
   fresh per-run writable artifact mount (prior output is not exposed), no
   inherited host environment or home-directory secrets, network disabled
   by default, dropped Linux capabilities, Docker CPU/memory/PID/time limits,
   explicitly bounded private `/tmp` and `/dev/shm`, disabled core dumps, and
   a best-effort output-size monitor. Docker is forced to `linux/amd64`, uses
   a bundled empty CLI config, never pulls, disables image healthchecks/logging,
   rejects images that declare implicit `VOLUME` mounts, and fixes no-device
   runs to `runc` while neutralizing NVIDIA/CUDA device-selection variables.
   Execution uses a
   named `docker create` followed by `docker start --attach`, then confirms
   Docker-client termination and daemon-side removal by the exact 64-character
   container ID returned by Docker.
5. Runs the project only in explicit **shadow** mode, captures bounded,
   target-controlled evidence about some attempted behavior, diagnoses
   failures, and never silently broadens permissions.
6. Reports static findings, authorization decisions, runtime evidence,
   replanning history, outputs, and a scoped security verdict.

## Status

This repository contains the first research MVP:

- bounded, execution-free repository/source/dependency analysis and a
  sanitized snapshot shared by analysis and execution;
- an explicit environment plan describing dependency declarations, image
  pinning, and whether a reviewed prebuilt image is still required;
- goal-conditioned capability reasoning baseline and fail-closed policy;
- Docker sandbox specification and explicit dry-run/shadow execution modes;
- runtime event collection and failure reflection;
- evidence-based security assessment, machine-readable JSON, escaped Markdown,
  complete per-attempt execution history, and a complete rerun argv plus
  source-snapshot digest. Raw target stdout/stderr, target-controlled event
  payloads, and artifact names are omitted from serialized reports;
- controlled benign/risky fixtures and a benchmark/research protocol. The test
  suite covers components and agent integration with mocked supervisors; a real
  Docker end-to-end suite is still pending.

The semantic reasoner is deliberately behind typed interfaces. The current
offline baseline is deterministic; an LLM backend can be evaluated later
without giving the model direct authority over the runtime.

## Current scope and limitations

- The CLI currently accepts local directories; URL acquisition and commit
  pinning are the next ingestion layer.
- Snapshot credential filtering covers common names such as `.env`, `.netrc`,
  `.npmrc`, cloud configuration directories, private-key suffixes, and common
  token/service-account JSON names. It is not a general secret detector and
  cannot recognize arbitrary filenames or encoded credentials. Treat the
  checkout itself as sensitive; production ingestion should default to pinned
  tracked files plus explicit data inputs and a bounded secret scanner.
- Snapshot ingestion rejects links/reparse points, multiply linked files,
  filesystem-device changes, and Linux submounts discovered through a bounded
  `/proc/self/mountinfo` read. Linux mount topology must remain stable for the
  whole copy. On non-Linux POSIX hosts, same-device bind/FUSE submount detection
  is platform-dependent; use a trusted, mount-free ingestion directory.
- Python and notebook behavior receive the richest static coverage. Shell,
  native code, model formats, and dependency CVE lookup are planned analyzers.
- Python audit events are explicitly typed as target-controlled and improve
  explanations only. They cannot decide **unsafe** or justify **safe**.
  The callback state is kept out of ordinary module globals and its event log
  is opened before hook registration, which removes a trivial in-module
  disable switch. The target process can still close or forge descriptors,
  mutate its interpreter, use native code, or otherwise evade this partial
  instrumentation. Independent kernel/host telemetry is future work.
- The approved initial Python entrypoint is forced with Docker `--entrypoint`,
  and process-spawn requests are denied by policy. The Python audit hook
  attempts to block covered Python subprocess APIs, but is not an enforcement
  boundary; native code or a compromised interpreter can still create child
  processes inside the container. A seccomp/AppArmor execution policy is
  future work.
- Output file/byte monitoring is best-effort, not a filesystem quota. An
  open-then-unlink writer can evade path scanning, and directory scanning has
  time-of-check/time-of-use races. Production needs a dedicated quota-capable
  filesystem or volume plus descriptor-relative (`dirfd`/`openat`) traversal.
- Docker bind-path validation and the daemon's later path lookup are separate
  operations. The MVP assumes the selected output root and every ancestor are
  trusted, private host directories that untrusted local principals cannot
  rename, replace, or write during validation, container creation, execution,
  and cleanup. A shared or attacker-writable ancestor invalidates the fresh
  output-child guarantee; production should use a pre-provisioned private
  volume or descriptor/handle-based mount mechanism.
- In-process errors and interrupts after container creation trigger bounded
  cleanup and a structured failure if Docker-client termination or container
  absence cannot be confirmed. A host power loss or uncatchable supervisor
  termination can still orphan a labeled container. Unattended production use
  requires an external lease/watchdog that removes stale
  `io.r-sandbox.managed=true` containers; the MVP is not that watchdog.
- Static parsers have byte, directory, AST, dependency, finding, and warning
  budgets, but still run in the host process. A resource-limited parser worker
  is planned.
- Dependencies are never installed on the host or implicitly in Shadow mode.
  Projects with third-party declarations require a reviewed prebuilt image;
  unsupported metadata is reported as incomplete coverage.
- The runtime never pulls an image implicitly. The selected trusted image must
  already exist locally, and production experiments should identify it by
  digest. The image filesystem and its `Config.Env` values are trusted inputs
  visible to the project; never bake credentials into the reviewed image.
  The no-host-environment guarantee does not scrub secrets already stored in
  that image.
- Shadow mode currently requires a Docker Engine/API that supports
  `docker image inspect --platform` (API 1.49 or newer). Both metadata
  inspection and execution are fixed to `linux/amd64`; older engines fail
  closed during image preflight.
- A real Shadow run requires Docker. If Docker is missing—or independent
  observation is absent—the result is **inconclusive**, not **safe**.
- Rerun argv is recorded as JSON rather than a shell string. A rerun creates a
  new sanitized snapshot; compare its digest with the original report before
  treating results as the same source state. A dry-run Docker preview contains
  a temporary snapshot path and is an audit record, not a durable command.
- Reports are local security artifacts, not automatically safe for public
  sharing: repository paths, file inventory, plans, dependency names, and
  source filenames/literals, environment-variable names, goals, timings,
  counts, and source-snapshot metadata may themselves be sensitive. Treat every
  report as untrusted, potentially sensitive content and review it before
  sharing. Redacted target values are omitted rather than exposed through
  guessable unkeyed hashes.

## Quick start

Python 3.11+ is required. Static analysis and dry-run planning have no runtime
dependencies.

For the local security workbench:

~~~powershell
python -m pip install -e .
r-sandbox ui
~~~

The browser UI binds only to `127.0.0.1`, generates a new session token on
every start, and keeps reports in browser memory unless you explicitly export
one. It exposes the same typed agent and deterministic policy path as the CLI;
it is not a separate privilege or approval layer. Because it controls local
files and Docker, it is intentionally not a hosted web application.

For direct CLI use:

~~~powershell
python -m pip install -e .
r-sandbox analyze examples/safe_research_repo --goal "reproduce the mean experiment"
r-sandbox dry-run examples/safe_research_repo --goal "reproduce the mean experiment"
~~~

Actual repository code runs only with the explicit command below and requires
Docker plus a previously reviewed local image:

~~~powershell
r-sandbox shadow examples/safe_research_repo --goal "reproduce the mean experiment" --output .r-sandbox/safe-output --report .r-sandbox/safe-report.json
~~~

Use the controlled adversarial fixture to demonstrate the security preflight:

~~~powershell
r-sandbox shadow examples/risky_research_repo --goal "run the published experiment" --output .r-sandbox/risky-output --report .r-sandbox/risky-report.md
~~~

The risky fixture uses only a synthetic canary and a reserved **.invalid**
domain. Do not replace them with real secrets or endpoints.

## Approvals and exit codes

`--approve REQUEST_ID` applies only to that invocation and only to the exact
canonical request shown in the report. Its ID is bound to the repository path
and snapshot digest, goal, category, action, target, risk, exact floating-point
confidence, justification, evidence, selected image reference, policy version,
and runtime backend/platform identity. Explicit approval is consumed only when
the image reference is SHA-256 digest-pinned. An approval cannot override a
hard denial. Approval tokens are not yet signed, expiring, or persisted with a
one-time nonce; production approval transport remains future work.

`--allow-domain HOSTNAME[:PORT]` narrows a requested download endpoint but does not
turn Docker networking into a hostname firewall. Shadow execution still fails
closed until an enforcing egress adapter exists. Capability comparison uses an
exact host and effective port; an omitted port means HTTPS port 443.

For `analyze` and `dry-run`, exit code `0` means the requested non-executing
operation completed and `1` means it was blocked or failed. For `shadow`, `0`
is reserved for a completed independently attested **safe** run, `3` means the
result is inconclusive/runtime-unavailable/awaiting approval, and `1` covers
review, unsafe, blocked, or failed results. Consequently the current Docker
backend normally returns nonzero for security-gate use even when target code
exits successfully.

## Safety properties

- Analysis mode never executes, imports, or installs target code.
- README commands are untrusted evidence and are not copied into a shell.
- Host-side Docker commands remain argument arrays with `shell=False`, and the
  approved exact initial executable overrides image `ENTRYPOINT`. Ambient
  Docker routing, proxy, platform, and API-version variables are not forwarded.
  This does not yet prohibit every child exec from native code inside the
  container.
- Shadow execution creates the exact named container before attaching the
  execution client. Every terminal path attempts client shutdown, force-removal,
  and repeated absence checks using only the exact Docker-returned container ID;
  a create/name collision never authorizes name-based deletion. An unconfirmed
  lifecycle step is a reported failure, never a successful run.
- The original repository is never mounted. Analysis and execution share one
  sanitized, read-only snapshot whose digest is bound into capability IDs.
- Network access is denied unless a separately enforcing, narrow egress adapter
  is available. A Docker bridge is not misrepresented as a domain allowlist.
- Host-secret access, arbitrary upload, host-path access, source mutation, and
  irreversible external effects are policy denials; enforcement strength and
  observation gaps are reported rather than hidden.
- The user-selected output root is never mounted wholesale. Each execution
  receives a newly and atomically created empty child, so prior reports,
  credentials, and artifacts are outside the container's view. Reads, writes,
  renames, and deletes inside that fresh staging area are treated as artifact
  operations, not host-side effects. This property depends on the documented
  trusted-private output-root and ancestor assumption; it is not guaranteed
  for a path another local principal can replace before Docker resolves it.
- Reports separate `security_gate_result` from workflow/execution `outcome`;
  a process may exit successfully while the security gate fails.
- A **safe** verdict additionally requires typed, run-bound independent
  host-side behavior coverage. The current backend does not accept or provide
  that attestation.

## Repository map

~~~text
src/r_sandbox/agent/    orchestration, planning, reasoning, reflection, reports
src/r_sandbox/tools/    source/dependency analysis, sandbox, execution, observer
src/r_sandbox/policy/   deterministic authorization boundary
policies/               reference schemas/policies (runtime source of truth is policy/engine.py)
examples/               benign and controlled-risk research fixtures
benchmarks/             evaluation protocol and future pinned corpus
docs/                   architecture and research methodology
tests/                  unit and mocked-runtime agent integration tests
~~~

See [architecture](docs/architecture.md) for trust boundaries and
[research plan](docs/research-plan.md) for hypotheses, baselines, ablations,
and metrics.
