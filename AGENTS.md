# Release follow-up

Do not add AI or Copilot references to code, comments, commit messages, or PR
titles and descriptions. Do not add AI or Copilot co-author or attribution trailers.

When updating this action or following up a release, check whether
`nais/docker-build-push` needs its `nais/attest-sign` dependency updated.
These instructions run only during an agent session; they do not watch releases.

1. Confirm that a stable, non-draft release of `nais/attest-sign` containing the
   intended changes is published. Resolve its version tag to the full commit SHA,
   peeling annotated tags. Do not pin an unreleased branch or a floating major tag.
   If the release is not published yet, report the downstream PR as pending.
2. Read `nais/docker-build-push`'s repository instructions, PR template, and current
   default branch. Inspect `action.yml` and any other `nais/attest-sign` references.
   If they already resolve to the release commit or a newer release, do nothing.
3. Check open PRs for the same dependency update. Reuse an existing matching PR
   instead of opening a duplicate; do not overwrite unrelated changes.
4. Create a separate branch in `nais/docker-build-push` from its default branch,
   named `build/attest-sign-<version>`. Update the dependency to the release's full
   commit SHA and keep the existing ratchet comment convention. Leave inputs and
   unrelated dependencies unchanged. Flag breaking changes rather than silently
   migrating callers.
5. Run the downstream repository's relevant checks and inspect the complete diff.
   Report failed or blocked checks accurately. Do not bypass sandbox restrictions
   or request broader credentials to finish the update.
6. Commit, push the downstream branch, and open a draft PR targeting that
   repository's default branch. Use the title
   `build(deps): bump nais/attest-sign to <version>` and the existing `dependencies`
   label; add `github_actions` if available. Follow the PR template and include the
   release link, old and new SHA, compatibility concerns, and check results.
   If checks are blocked, state that explicitly in the PR.
7. Leave the PR for human review and merge. Never merge it, enable auto-merge,
   publish a release, or move tags as part of this follow-up. Report the PR URL,
   or the exact blocker if permissions or repository access prevent its creation.
