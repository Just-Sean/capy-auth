# Changelog

Newest version first. For each version: what changed, and **what a project must do
when it upgrades** (a new setting, a migration that deletes data or is slow on big
tables, an extension the project must add first, or "deploy vX.Y.Z first" when this
version finishes a change the one before it started), or "nothing".

## 0.1.0

- First version. Projects: add it as the README's "Add it to a project" says.
  Migration 0004 reads every user once (in batches of 1,000) to add their email to
  allauth's list; on a big users table it takes a while.
