# AGENTS.md

Guidance for AI agents working in this repository.

- **No AI attribution, org-wide**: commit messages carry no co-authorship trailers naming
  an AI model, assistant, or vendor, and PR bodies, issues, and comments carry no
  tool-credit footers or badges. windows-fileserver-ha enforces this with commit hooks
  that reject even a mention of such names or attribution phrases in messages and staged
  content; the rule applies to every nwarila-platform repository regardless.
- This repository is part of the nwarila-platform fleet normalization:
  **pdq-deploy-inventory is the Golden Repo** for structure, coding style, workflows, and
  least privilege. Defer to its patterns before any check-in unless this repository has a
  stated reason to differ.
- `main` is protected (PRs only, squash merges, signed commits, code-owner review): work on
  feature branches, never push to `main`.
- The `.gitignore` is DEFAULT-DENY: a new file must be allowlisted there, by exact name,
  before it can be committed. That is deliberate — publishing a file is an explicit act.

## The development contract

Substantive changes follow the org's separated-roles pipeline. The maintainer's workspace
holds the authoritative role assignments; they are deliberately not committed here.

- The **planner** researches this repository, the Golden Repo, and live state, and writes
  the plan: goal, constraints, golden reference paths, ordered steps naming the files
  touched, acceptance criteria, and audit notes. The planner never edits files.
- The **gate** reviews the plan alone and accepts or rejects it with the defects named.
  Silence is not acceptance.
- The **implementer** develops exactly what was accepted, on a feature branch. A blocker
  or a better idea returns to the planner for a revised plan — it never licenses deviation.
- Independent **auditors** then review the diff against the plan and the Golden Repo, one
  per domain below, and the change proceeds only at zero open findings. A domain with
  nothing to say returns "clean", not silence.

Audit domains:

1. **Total argument definition** — every Ansible module argument is statically defined; no
   implicit defaults (the Golden Repo's tasks are the standard).
2. **Simplicity** — each step is the simplest, most readable version of itself that is
   still correct.
3. **Golden style alignment** — naming, task-title form, banners, layout, and idiom match
   pdq-deploy-inventory; ratified deviations are the local standard.
4. **Comment discipline** — a comment is concise and expresses only what the code itself
   cannot; narration and restated defaults are findings.
5. **Plan conformance** — the diff achieves the plan's goal, completely and nothing
   beyond it; scope creep is a finding even when the extra change is good.
6. **Least privilege** — touched AWS/IAM/S3 surfaces stay inside the ratified target
   model: exact paths, tag-scoped actions, no new wildcards. Needing more access is a plan
   revision, not a permission bump.
7. **Idempotency and convergence honesty** — a second run converges to the documented
   recap; destructive operations are guarded; changed_when/failed_when state the truth.
8. **Publishing discipline** — new files deliberately allowlisted; no process artifacts,
   secrets, or attribution anywhere in the change.
9. **Determinism and pinning** — everything version-addressable is pinned; framework pin
   files are never hand-bumped; nothing installs "latest".
10. **Failure honesty** — errors fail loudly and name their cause; no swallowed exit
    codes; success is verified against reality, not a tool's report of itself.
