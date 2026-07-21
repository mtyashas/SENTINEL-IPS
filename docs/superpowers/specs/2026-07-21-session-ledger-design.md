# Session Ledger — Design Spec

**Date:** 2026-07-21
**Status:** Approved

## Purpose

The user (project owner) needs a running, dated record of what happened in
each working session with Claude Code on SENTINEL IPS, so they can quickly
re-orient themselves and brief teammates without re-reading chat history or
git log. This spec defines the ledger file's format and the standing
assistant behavior that keeps it updated.

## Decisions

### 1. File location and structure

A single file: `docs/SESSION_LEDGER.md`.

- Newest session entry is prepended at the **top** of the file (below a short
  header explaining its purpose), older entries pushed down.
- Single file rather than one-file-per-session: easier to skim top-to-bottom,
  easier to grep/search across sessions, shows up as a normal diff in git
  history.

### 2. Entry template

Each session gets one entry using this exact structure:

```markdown
## YYYY-MM-DD — <short session title>

**Goal:** What we set out to do this session.

**Changes:** What actually got built/changed/decided in concrete terms
(files touched, features added, results produced).

**Decisions:** Key choices made and the reasoning, especially anything
non-obvious a teammate would need to know to not redo the debate.

**Next steps:** What's queued up for the following session.

---
```

Fields are: Goal, Changes, Decisions, Next steps. All four are always
present; write "None" or a one-line "n/a" note if a field genuinely doesn't
apply to that session rather than omitting the heading.

### 3. Assistant behavior (ask / track / record cycle)

This behavior is encoded as a standing instruction in `CLAUDE.md` (loaded
and enforced automatically every session) since there is no other mechanism
for it to persist across separate conversations.

- **Session start:** before starting any work, ask the user: *"Log this
  session to the ledger?"* This is a single yes/no check, asked once near
  the top of the conversation.
- **During the session:** if the user opted in, keep track of the session's
  goal, concrete changes, decisions, and any forward-looking next steps as
  the conversation progresses. No visible action needed from the assistant
  during this phase beyond normal work.
- **Session end:** the user triggers recording by saying a stop phrase —
  "stop session", "end session", or "wrap up" (or an obvious equivalent).
  On hearing it, the assistant drafts an entry using the template in
  section 2, summarizing that session, and prepends it to
  `docs/SESSION_LEDGER.md`.
- **No stop phrase, no entry:** if the conversation just ends without the
  user saying a stop phrase, no ledger entry is written for that session.
  The stop phrase is the explicit save trigger — this is intentional so the
  user controls exactly when a session's record is finalized (e.g. after
  confirming everything discussed is accurate).
- If the user declined logging at session start, the assistant does not ask
  again later in that same conversation and does not write an entry even if
  a stop phrase is said.

### 4. Bootstrapping

`docs/SESSION_LEDGER.md` is created with:
- A one-paragraph header explaining the file's purpose and the ask/stop
  protocol, so the format is self-documenting for anyone who opens it.
- A first real entry documenting the current session (the SENTINEL project
  status brief given to the user, and the design/build of the ledger
  system itself).

## Out of scope

- No enforcement mechanism beyond the CLAUDE.md instruction — this is a
  convention the assistant follows, not code that runs independently.
- No automatic session-end detection (e.g. inferring from silence or
  conversation close). The user's explicit stop phrase is the only trigger.
- No structured/machine-readable format (e.g. JSON/YAML) — the ledger is
  for human reading, plain markdown only.
