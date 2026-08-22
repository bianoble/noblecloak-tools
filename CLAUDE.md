# noblecloak-tools

Project guidance for Claude Code. See the workspace-level `CLAUDE.md` in `IdeaProjects/` for cross-repo context.

## Capability tagging (per ADR-0032)

If your PR moves a capability's status (toward `beta` or `shipped`), select the matching `Capability: <id>` in the PR template. The bridge will append your PR to that capability's contributing-PR list in osvault. Capability promotions (status transitions) are owner actions and happen separately — you don't need to update the capability file yourself.

If your PR is a refactor / chore / infra change that doesn't move a capability, select `Capability: none`. That's the right answer for a meaningful fraction of PRs and the matrix doesn't want them.

For the full set of capability IDs, see [osvault Capabilities/](https://github.com/bianoble/osvault/tree/main/Capabilities) (the directory listing IS the canonical list).
