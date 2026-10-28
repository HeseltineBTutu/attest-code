# Security Model

## Trust boundaries

1. Invariants are authoritative only after explicit human approval.
2. Model-generated invariant suggestions remain untrusted drafts.
3. Model-generated tests may supplement verification but cannot replace or
   weaken approved requirements.
4. Approved invariant changes require a new version and renewed approval.
5. Meta model output is untrusted input.
6. The verifier, not the model, determines the final verdict.
7. The model cannot change the approved invariant registry through its repair
   workflow.

## Approval boundary design

- Definitions (YAML) carry `id`, `version`, `requirement`, and `scope`. A
  definition file may contain an `approved` key for human convenience, but the
  loader ignores it (`IGNORED_DEFINITION_KEYS`).
- Authority comes only from an `ApprovalRecord` created via
  `create_approval`, which must be invoked by a human-driven flow (CLI review
  command or review UI — planned, not yet implemented).
- Each approval binds `(invariant_id, invariant_version, content_digest)`.
  Any change to the requirement, title, or scope changes the digest and
  invalidates prior approvals.
- The registry refuses approvals with no matching definition and refuses to
  resolve definitions without a matching approval.

## Limitations (explicit)

- Current approval records are in-memory/file objects with no cryptographic
  authorship: anyone with write access to the approval store could forge a
  record naming a reviewer. No signing infrastructure exists in this phase.
- Hashing (SHA-256 over canonical JSON) detects changes relative to a trusted
  digest. It does not establish authorship or authenticity.
- `approved_at` is a caller-supplied string; no trusted timestamping.
- `attest review` is the human approval flow: it shows the invariant with its
  content digest and prior approval state (none, MATCH, or STALE), requires
  `--approver` naming the reviewer, and writes to the YAML approval store
  only on explicit `y`/`yes` confirmation. Tests act as that operator via
  explicit fixtures, never as model output.
- `run_verification` and `attest verify` enforce the boundary at invocation:
  a missing or stale approval refuses verification instead of verdicting.
- No sandbox isolation exists yet; untrusted execution stays disabled.
  Checks run in worker subprocesses via a FastAPI test client, and only
  verifier-owned check code runs — model-provided code is never executed.

## Revision integrity (MVP policy)

- `attest verify --revision <rev>` resolves `<rev>` to a full 40-hex commit
  id and records that id, never the raw label.
- `--repo` is canonicalized to an absolute path and must be the work-tree
  top level; subdirectories, files, and non-repositories are refused.
- Verification refuses unless HEAD equals the requested commit (check it out
  first; the tool never switches branches) and the snapshot scope is clean:
  `src/`, `tests/`, `invariants/` show no staged, unstaged, or untracked
  changes, and the root files `pyproject.toml`, `uv.lock`, `.gitignore`,
  `.gitattributes` are each committed-and-clean or absent. Untracked root
  files outside that set (notes, approvals, evidence) are ignored because
  they influence neither imports nor the interpreter.
- Ignored-file detection (F3 fix): before any attempt runs, verification
  refuses when a git-ignored file with an importable suffix (`.py`, `.pyc`,
  `.pyo`, `.so`, `.pyd`) exists under `src/`, or when a tracked file
  anywhere in the snapshot scope carries an index flag that hides worktree
  changes. Both flags are detected via `git ls-files -v` (lowercase tags
  for assume-unchanged, `S` for skip-worktree — lowercase alone would miss
  the second), which also means sparse checkouts, whose excluded files
  carry skip-worktree bits, are refused rather than verified. Only
  bytecode copies under a `__pycache__/` segment are excluded (tagged cache
  names are never directly importable; a `.py` source there is flagged);
  ignored files outside `src/` are out of the importable scope. Ignored
  directory symlinks under `src/` are a known residual: they cannot shadow
  same-named tracked entries, and dotted imports through them are not used
  by the verifier. The before/after fingerprint covers the same scan, so a
  file planted mid-run still flips the verdict to INCONCLUSIVE — but a
  plant-and-revert fully inside one attempt remains invisible (see the
  guarantees section below).
- Module-origin binding (F1 fix): `attest verify` proves the executed
  verifier/demo packages (`attest_spec`, `attest_core`, `apps`, `examples`)
  resolve inside the snapshot-enforced tree, both for the already-loaded
  parent modules and via a spawned worker probe that reports where the
  worker itself would import them. Unresolvable, namespace, zip, foreign
  checkout, installed-copy, or `PYTHONPATH`-shadowed modules fail closed
  with an integrity error (exit 3) before any attempt runs, so no evidence
  can claim a revision was tested.
- Invariant and approvals inputs must live inside `--repo`; paths outside
  (including `..` escapes) are rejected.
- A fingerprint (HEAD id plus relevant status) is taken before and after the
  run; a mismatch overrides any verdict with INCONCLUSIVE and is flagged in
  the output (`snapshot-changed: true`). Each attempt is additionally
  fingerprinted before and after it runs: drift that persists past any
  attempt boundary fails that attempt as an infrastructure failure (with
  the drift recorded in its evidence), which yields INCONCLUSIVE under the
  unchanged verdict policy. Dirt planted and reverted strictly inside one
  attempt remains invisible — sampling a live worktree cannot bind the
  exact bytes a worker executed. True per-attempt byte identity needs
  immutable execution (verifying an exported snapshot rather than the live
  tree), which is future work, not claimed here.
- Worker bytecode caches are isolated per run: `attest verify` points
  `PYTHONPYCACHEPREFIX` at a fresh temporary directory before the first
  child spawns, so workers neither read bytecode planted in the tree's
  `__pycache__/` directories nor write caches into the tree. The prefix is
  execution hygiene, not identity: its random path is deliberately excluded
  from the configuration digest. The parent's own imports happen before
  this takes effect, so parent-side cache poisoning stays inside the
  trusted-launch boundary (a hostile tree must not be verified via an
  interpreter that already imported from it).

## Runtime and environment binding (F2 fix)

- Import-affecting overrides are validated before any attempt runs:
  `PYTHONHOME` is refused outright (it relocates the stdlib); every
  `PYTHONPATH` entry must resolve inside `--repo` (empty entries resolve
  against the working directory; nonexistent entries are still refused so
  they cannot be planted mid-run). Anything else fails closed with an
  integrity error (exit 3).
- Autoimported startup modules tied to the repository root are refused by
  a preflight that runs before the first child process is spawned: a
  `sitecustomize.py` or `usercustomize.py` present as a file or symlink
  (tracked, untracked, ignored, or dangling) aborts verification, as does
  an already-imported startup module attributable to the tree (e.g. a file
  that executed and deleted itself during interpreter startup).
  The preflight cannot reverse code that already ran: a startup module
  executed in the parent before `main()` — via the working directory under
  cwd-on-path entry points, or via `PYTHONPATH` entries resolving to the
  root — may already have altered interpreter state or scrubbed its traces
  (deleted file, cleaned `sys.modules`), which no in-process check can
  detect. Supported invocation is the installed `attest` console script
  with an operator-controlled environment; running verification from a
  hostile tree via `python -c`/`-m`, a script, or pytest is outside the
  trusted-launch boundary. Startup hooks inside `site` directories, `.pth`
  handling, and `usercustomize` under `HOME` remain trusted computing base
  (a writer there already owns the interpreter). `PYTHONSTARTUP` is inert
  (workers are never interactive).
- The run configuration digest additionally binds the Python
  implementation/version, the normalized `PYTHONPATH`, the installed
  versions of the runtime dependency closure (`deps.*`, discovered from
  the installed distribution metadata; `absent` when missing), and the
  SHA-256 of `pyproject.toml`, `uv.lock`, `.gitignore`, and `.gitattributes`
  (`absent` when missing).
  The same settings object feeds all three attempts, so intra-run config
  drift is impossible by construction; a changed environment produces a
  different digest rather than a comparable verdict.
- Explicitly not claimed: recorded versions describe the environment but
  are not compared against `uv.lock`, so the lockfile hash records which
  lockfile was present, not that installed packages match it.
  Installed-dependency verification, full worker-environment scrubbing,
  and the `git` binary on `PATH` itself remain trusted computing base,
  as do `.git/config`, filter drivers, hooks, and submodule contents
  (only the gitlink pointer is observed).

### Remaining origin limitations

- Path binding plus a clean tree is not a proof of exact executed bytes:
  it shows the loaded files live in the attested snapshot, not a hash of
  what the interpreter executed. Installed third-party packages and the
  interpreter binary remain recorded-but-unverified (audit item F4).
- There is a check-to-execution window: files could change after the origin
  probe and before a worker imports them. Net changes are caught by the
  before/after fingerprint; transient change-and-revert inside the window
  is not (audit item F6).
- The binding assumes the operator's Python resolves `find_spec` the same
  way in parent and worker (same `sys.path`, cwd, environment, which spawn
  inherits). Exotic importers (meta-path finders, custom loaders) are
  outside the MVP threat model.

## What each guarantee does and does not mean

Keep these four distinctions separate when reading any verdict:

- **Snapshot integrity** establishes a defined repository-state boundary:
  the recorded commit is checked out, the snapshot scope is clean, and no
  ignored-executable or index-flag-hidden files lurk in the executable
  scope. It says nothing about code outside that boundary (`.git/`,
  the toolchain, the filesystem outside `--repo`).
- **Runtime binding** records selected settings (interpreter,
  `PYTHONPATH`, manifest hashes) in the configuration digest so runs are
  comparable and drift is visible. It does not prove installed
  dependencies match `uv.lock`, and it does not verify the interpreter.
- **Environment validation** refuses obvious import overrides. It is not
  sandbox isolation: workers share the operator's privileges and
  filesystem, and malicious target code remains out of scope until a real
  sandbox exists.
- **Hashes, OIDs, and fingerprints** provide tamper-evidence relative to a
  trusted value, not authenticity: nobody has signed anything, and a
  reproduced digest never proves who produced a run. Before/after checks
  also leave a time-of-check/time-of-use race: a change planted and
  fully reverted strictly inside one attempt is invisible by construction.
  The revision OID names the commit the tree matched at the sampled
  instants; it is not a hash of the bytes each worker executed.

## Bounded execution

- Each attempt runs in a spawned subprocess with a wall-clock deadline
  (`--timeout`, default 60s). Expiry terminates the worker (SIGTERM, then
  SIGKILL); an expired, crashed, or erroring worker yields an
  infrastructure outcome, so timeouts and crashes give INCONCLUSIVE and can
  never alone establish FAILED.
- Limits: workers run with the operator's privileges and share the
  filesystem; this bounds stuck execution but is not a sandbox against
  malicious code. Worker callables must be picklable top-level references.
  A bare `run_verification` library call remains in-process and unbounded;
  only the CLI path applies deadlines.

## Endpoint inventory mechanism

- `admin_route_paths` inventories registered routes whose path starts with
  `/admin`, sorted for determinism.
- Checks require exact correspondence between declared scope and actual
  routes: an undeclared admin endpoint, a declared-but-missing endpoint, or
  an unreadable inventory all fail closed to an infrastructure outcome
  (INCONCLUSIVE), never a silent pass or a claimed violation.
- Limitations: prefix-based only; mounted sub-applications, dynamic routes,
  and admin behavior under non-`/admin` paths are not discovered. Probes use
  GET only and distinguish paths, not methods. The inventory does not claim
    to discover every possible dynamic or indirectly exposed endpoint.

## Verdict policy

- FAILED requires a reproducible invariant violation across three independent
  attempts under the same recorded revision and configuration, each with
  evidence.
- Timeouts, crashes, missing evidence, mixed results, scope-coverage gaps,
  and revision/config mismatches yield INCONCLUSIVE, never FAILED.
- PASSED is the policy's verified outcome: all required checks passed in all
  three attempts with scope coverage established.
- No universal proof of correctness is claimed. Each classification states
  precisely what was checked (attempt count, same-revision/config rule,
  evidence presence).
- The three-attempt rule is not a universal guarantee against
  nondeterminism: attempts run in separate worker processes but on one
  machine without execution isolation, so they catch flaky or
  non-reproducible results but cannot prove determinism.

## Model-data hygiene (planned integration)

- Keep model calls separate from verification execution.
- Never send secrets, private credentials, or unrelated repository contents.
- Send only the failing invariant id/version, the minimal failing evidence
  excerpt, and the implicated code region.
- Mock results must never be presented as evidence of a real Meta API
  integration.
