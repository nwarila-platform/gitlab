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
