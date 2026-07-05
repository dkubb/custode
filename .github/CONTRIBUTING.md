# Contributing

Thanks for your interest in improving this project. This document covers the
conventions we ask contributors to follow; most of them exist to keep the
history and review queue easy to read.

## Local Checks

Run the full gate before opening a pull request:

```console
just check
```

This runs formatting, lints, shell checks, tests, and the Dockerfile check.
Individual targets (`just fmt`, `just lint`, `just test`, and others) are
listed by running `just` with no arguments.

## Pull Requests

Start from `.github/pull_request_template.md` and fill in only the sections
that apply. A good description is short, specific to the branch, and easy to
review.

Assign the pull request to whoever is doing the work.

Title pull requests using conventional commit syntax:
`type(scope): imperative summary`.

### Summary

List the changes as bullet points, ideally one per commit and in commit order.
Reuse the action verbs from the
[`atomic-changes` skill](https://github.com/dkubb/skills/blob/main/skills/atomic-changes/SKILL.md)
rather than coining new phrasing, so summaries stay consistent across pull
requests without duplicating text that could drift.

### Description

Explain why the change exists and what it does. Cover how it works only when
the approach is unusual or the mechanism matters. Skip `What`, `Why`, and
`How` headings — plain prose is enough.

### Dependencies

Add this section only when the pull request genuinely depends on others, such
as a stacked branch. Sort the list topologically, marking merged dependencies
with `[x]` and pending ones with `[ ]`.

### Acceptance

Reserve this section for verification a human must perform. If everything is
already covered by CI — formatting, lints, tests, and similar gates — leave it
out.

## Commits

Prefer small, atomic commits: each commit should have a single reason to
exist and should stand on its own under review. Every commit on the branch —
not just the branch head — should pass `just check`, so the history stays
bisectable and each commit can be verified independently. The decomposition
and ordering guidance in
[`atomic-changes/references/commits.md`](https://github.com/dkubb/skills/blob/main/skills/atomic-changes/references/commits.md)
describes the preferred approach.

If an agent is preparing or updating a non-trivial pull request, it should ask
whether the branch ought to be reorganized into reviewable atomic commits
before it lands. The author can do the cleanup, decline it, or record a local
memory so the same answer applies automatically in future sessions.

### Commit Messages

Write commit subjects in the semantic action-verb form from the
[`atomic-changes` skill](https://github.com/dkubb/skills/blob/main/skills/atomic-changes/SKILL.md):
`<Verb> <imperative summary>`. Conventional commit prefixes belong in pull
request titles, not in git commit subjects.

Keep the subject short and imperative, with no trailing period. When a commit
needs a body, leave a blank line after the subject and wrap the body at 72
columns, as described in
[A Note About Git Commit Messages](https://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html).
The body should briefly say what changed and why; describe the implementation
only when it is novel or would not be obvious from the diff. Do not use
`What`, `Why`, or `How` labels.

Across commit messages, pull request descriptions, and review comments, aim
for clear, concise language.
