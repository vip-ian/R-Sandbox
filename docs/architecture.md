# Architecture

R-Sandbox is a research-security agent. Its product boundary is the full agent
workflow; the sandbox is one enforcement and evidence-collection tool beneath
that agent.

```text
repository + research goal
            |
            v
  Repository Understanding ----> Source / Dependency evidence
            |
            v
    Permission Reasoning -------> capability contract + rationale
            |
            v
  Deterministic Policy Engine --> allow / deny / approval required
            |
            v
     Sandbox Builder -----------> snapshot:ro, fresh run output:rw, no host env,
            |                     network:none, bounded resources
            v
  Shadow Execution + Observer --> partial target-reported behavior evidence
            |
            v
 Reflection / Re-plan ---------> smallest safe change, never silent widening
            |
            v
 Security Assessment + Report -> safe / review / unsafe / inconclusive
```

## Trust boundaries

- Repository content, README instructions, model files, notebooks, and build
  metadata are untrusted data.
- Semantic reasoning may propose a capability and explain its relation to the
  research goal. It cannot grant that capability.
- The deterministic policy engine validates every proposal. Unknown values
  fail closed; hard denials cannot be overridden by an approval token.
- A verified local Docker/Linux daemon is the current containment boundary.
  Ambient remote Docker hosts/contexts are rejected. Python audit hooks and
  log parsers are target-controlled, cover only part of attempted behavior,
  and are not treated as containment or independent evidence. The bundled
  hook keeps its registered callback state in an unexported closure and opens
  its log descriptor before registration, removing a trivial module-global
  off switch. That is defense-in-depth only: the target can still tamper with
  its interpreter, close or forge descriptors, or evade Python-level events.
- Analysis mode never imports or executes repository code.
- The optional browser workbench is a local control surface, not a new
  authorization layer. It binds only to `127.0.0.1`, requires an ephemeral
  header token, verifies the exact Host and Origin, emits no CORS permission,
  and keeps reports in browser memory unless the user exports one. Manual path
  entry has the same authority as the invoking desktop user. Its optional
  model tool cannot choose a filesystem path and can only statically analyze
  the exact repository already selected in the visible form. Shadow requests
  require a separate exact boolean confirmation at the HTTP boundary.
- Shadow mode is explicit. A sanitized source snapshot is read-only; only a
  newly created per-run artifact directory is a persistently writable host
  bind. Prior output and host
  credentials are not exposed, network
  is disabled by default, Linux capabilities are dropped, and resource limits
  are mandatory. Private writable `/tmp` and `/dev/shm` are explicit typed
  capabilities with size bounds; they are ephemeral and are not host binds.
- Host validation of a bind path and Docker daemon resolution of that path are
  not one atomic operation. The output root and every ancestor are therefore
  assumed to be trusted, private host directories that no untrusted local
  principal can write, rename, or replace through container creation,
  execution, and cleanup. Under attacker-writable ancestry, a path-substitution
  race can invalidate the fresh-child isolation claim; production requires a
  pre-provisioned private volume or descriptor/handle-based mount facility.
- Snapshot ingestion rejects links/reparse points, hard links, device changes,
  and nested Linux mount points. Linux mount topology is checked before and
  after copying. Non-Linux same-device submount detection is platform-dependent,
  so those deployments require a trusted, mount-free ingestion directory.
- The Docker lifecycle is two-phase: the fully constrained named container is
  created first; its exact Docker-returned 64-character ID is then started with
  a fixed `start --attach` command. Terminal
  paths separately verify Docker-client shutdown and daemon-side container
  absence by that ID. Name collisions never trigger name-based deletion.
  Failures become supervisor evidence and prevent success.
- Docker metadata inspection and execution use the same fixed
  `linux/amd64` platform, a bundled empty Docker CLI configuration, and no
  ambient proxy/API-version settings. Image-declared `VOLUME` mounts are
  rejected. When no GPU was approved, the runtime is explicitly `runc` and
  NVIDIA/CUDA enumeration variables are neutralized. This requires Docker
  Engine API 1.49 or newer.
- The reviewed image filesystem and image `Config.Env` are trusted runtime
  inputs and remain visible to the project. Host environment variables and home
  mounts are not inherited, but credentials baked into an image are not scrubbed;
  reviewed images must not contain them.

## Agent loop

The orchestrator records each transition:

1. **Observe** — accept a repository and a natural-language research goal.
2. **Understand** — identify entrypoints, data, dependencies, and behavior.
3. **Plan** — select a bounded experiment path, never a copied README shell
   string.
4. **Authorize** — compare proposed/observed capabilities with fail-closed
   policy.
5. **Build** — translate allowed authority into a sandbox specification.
6. **Execute** — run the sanitized snapshot with a fresh artifact mount when
   explicitly requested. Container identity is fixed before target code starts.
7. **Monitor** — collect bounded target-reported Python events, exit/output
   streams, and host-side artifact scans; coverage gaps stay explicit.
8. **Reflect** — distinguish dependency, permission, command, and resource
   failures.
9. **Re-plan** — apply only the supported alternate-interpreter change after
   runtime schema validation; authority expansion
   stops for approval.
10. **Report** — preserve the plan, decisions, evidence, verdict, complete rerun
    argv, every execution attempt, and source-snapshot digest. Raw target
    streams, target event payloads, and artifact names are omitted. Reruns recreate a snapshot and must compare
    the new digest; temporary dry-run mount paths are not durable commands.

## Security verdict semantics

`safe` additionally requires complete static coverage, a suitable immutable
environment, no denied observations, successful execution, and an independent
host-side behavior-coverage attestation bound to the unique run, source
snapshot, image, platform, and argv. The current Docker backend cannot produce
or accept that attestation, so it cannot emit `safe`. Its Python events are
target-controlled, so the bundled backend also cannot independently establish
`unsafe`; a separately trusted observer adapter must provide typed independent
evidence. Even a future `safe` applies only to the tested path and supplied
inputs, not every program path. `review` means the goal may legitimately
require a held permission or evidence is ambiguous. `unsafe` means a trusted
independent observer found secret access, data egress, destructive behavior, or
another high-impact contract violation. A confirmed
resource/output quota breach produces `review`, because it violates the approved
contract without by itself proving malicious intent. `inconclusive` means the
dynamic preflight did not run or could not produce sufficient evidence.

Workflow/execution outcome and security-gate result are separate report fields.
A successful target exit never implies that the security gate passed.

Serialized reports still contain repository/output paths, source filenames and
literals, inventory, goals, dependency and plan metadata, environment-variable
names, timings, and counts. They are untrusted, potentially sensitive local
artifacts rather than publication-ready redactions and must be reviewed before
sharing.
No in-process cleanup protocol survives host power loss or an uncatchable
supervisor kill; production deployment needs an external lease/watchdog for
stale containers carrying the `io.r-sandbox.managed=true` label.

## Planned enforcement layers

The MVP prioritizes filesystem scope, outbound network denial, and isolation
from host environment secrets. Secrets already baked into the reviewed image
are outside that guarantee. Domain-level egress requires an enforcing proxy; Docker's
plain bridge network is deliberately not presented as a domain allowlist.
Linux seccomp/AppArmor and eBPF-based observation are follow-up enforcement and
telemetry layers. The current output monitor is reactive and best-effort, not a
hard quota; quota storage and descriptor-relative traversal are follow-up work.
GPU passthrough remains coarse (`--gpus all`), opt-in, and separately
approved. A lower-authority device-inspection request is denied because the
runtime cannot enforce it distinctly.
