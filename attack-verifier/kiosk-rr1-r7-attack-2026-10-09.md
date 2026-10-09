# Attack: kiosk Reset fix (R7, RR1), abg-fleet-updates fix/kiosk-rr1-r7 @ 41ac9ec5 (2026-10-09)

Verifier: AoC Verifier, **Opus 5.5**. Builder: **Sonnet 5.5** (verifier ABOVE the builder). Member-facing (the shell can
end a member's game once companion is on). Base: fleet main 097b3b5 (BayAgent 1.4.0, kiosk shell shipped OFF).
Worktrees: `C:\aoc-wt\kiosk-rr1-r7-attack` (branch `verify/kiosk-rr1-r7`, evidence in `attack-verifier\`),
`C:\aoc-wt\kiosk-rr1-r7-attack-run` (detached 41ac9ec5, clean, suite runs). No live bay command, nothing to Bay 1, no Dev
write, nothing published. Everything below is measured or my recommendation; nothing here was ruled.

## VERDICT

| Scope | Verdict |
|---|---|
| **fix/kiosk-rr1-r7 @ 41ac9ec5 as code (dormant 1.4.x, companion OFF)** | **MERGE.** Strictly narrows what a Reset can do; no regression in anything that blocks; tests fail on 097b3b5 for the right reason; mutants confirmed. |
| **The A0.460 companion gate "RR1 with R7"** | **NOT MET. Do not lift the gate on this fix.** The fix keys "is a member playing" on session.json's status, which four other writers move off ACTIVE/ENDING while a member is still playing (an emergency stop that was cleared, the next booking's Prep at end minus 15, a late End of the previous booking, a stale end). In each, a canceled booking's Reset still restarts the wall, sets the facility Idle and writes READY; and with RR1's precondition (an intent write that keeps failing) the shell then ENDS the paying member's game (X1b, measured through the real handler and the shell's real decision functions). The builder's record line "with R7 closed a Reset can no longer turn a running B's session.json to READY" is false for the e-stop case: the suite's e-stop is a stub that never writes STOP. |

### Required fixes (block the companion release; not this merge)

- **RF-K1: decide "a member is playing" from a fact no other command moves, not from session.json status.** Options (my
  recommendation, builder's choice): the agent persists its own running-session record at Start (id + end) and clears it
  only at that session's End or end + grace; a Reset is skipped while that record is live and the Reset does not name it.
  The Reset ROW already carries the canceled session (`build_BaySession@odata.bind` in
  DataverseBayCancelEndSessionWriter); the agent can read `_build_baysession_value` with the command and compare, no
  platform change needed. Pin with: the REAL Invoke-EmergencyStopInternal (engage, clear, Reset), the next booking's Prep
  during play then its cancel Reset, a late End of the previous booking after the next Start then a Reset, and a stale
  end with a lost extension display.
- **RF-K2: the RR1 class is still open without any Reset (X2b).** With an older "closed" held by a failing intent write,
  the next booking's Prep at end minus 15 writes PREP, which the shell's guard allows a close on: the playing member's game
  is ended 15 minutes early. The prior verdict's remedy still applies: the shell acts on a closed intent only when
  session.json shows ENDED naming that closed intent's own session, or holds any close while the agent reports a pending
  intent write through a file the shell can read.

### Named residuals (do not block)
- **N1 `force` is read with `[bool]`, so any non-empty string or object is true** (X6: `"false"`, `"0"`, `"no"`, `{}`,
  `{"FORCE":"x"}` all proceed as force; JSON `false`, `0`, `null`, `[]` hold). Nothing sends `force` today (checked: the
  only platform Reset producer is DataverseBayCancelEndSessionWriter, payload fixed; OpsFleetFunction is GET-only; the
  other bay-command writers send no Reset). Against the guard plugin (portal f8bebbe8): `HandleCreate` validates the payload
  ONLY for StartProcess, and the per-bay lock (A0.458) applies to UPDATES of execution fields, so any principal that can
  create a bay command can send `{"force":true}`. That adds no reach: the same creator can already send an EndSession with
  no id (sameSession defaults true, the base handler closes the launcher) or a Reset naming the running session. Recommend
  accepting only a JSON `true` literal and recording `force` in the result, before anything starts sending it.
- **N2 the stale rule releases a still-running session in two shapes** (X4, X8): (a) an extension whose display update was
  not queued (best effort in DataverseBaySessionExtensionReplanner; it relies on the Warn5 at the new end) leaves the old end
  in session.json, so from old end + 15 to new end - 5 a cancel Reset proceeds during paid extended time; (b) a bay clock
  fast by more than 15 minutes plus the time left (+20 min releases a session with 4 real minutes left; +76 min releases a
  60-minute session at its start). Harm today: wall, display and facility (see RF-K1), not the launcher, except through RR1.
- **N3 the builder's residual "a Reset for a booking whose own session is running is skipped; its End will end it" is
  wrong on the second half.** The cancel writer cancels every Pending command of that session, End included, and queues
  only the no-id Reset, so nothing ends a session canceled mid-play (X10): the wall keeps its countdown and, in companion,
  the intent stays wanted until end + grace, so the shell keeps the launcher for the canceled booking. On 097b3b5 the Reset
  wrote READY and the launcher also stayed open (Reset never closed it), so the change is the wall and the companion
  restart backing; no member is harmed. RF-K1's session-bound Reset (the row names the canceled session) fixes it too.
- **N4 session.json shapes the gate reads as "nobody playing"** (X5): 0 bytes, whitespace, NUL-filled (a power-loss
  shape), BOM only, `null`, `[]`, truncated JSON, UTF-16, `{}`, a lowercase or space-padded status, a duplicate status key
  (last wins). The agent writes atomically (temp + File.Replace) and upper-cases status, so only power loss, a failed
  non-atomic fallback, or a hand edit produce these; the builder stated "unreadable proceeds, as before".
- **N5 a skipped Reset is recorded Succeeded** (Process-Command), visible only in the result JSON (`skipped`, `reason`).
  A reordered Reset-then-End leaves the bay on ENDED until the next Prep (X9); nothing retries the skipped Reset.
- **N6 tests:** the K18b "gate: id compared case-sensitively" assertion pins a choice, not a safety property (a Reset that
  names its own GUID in another case or with braces holds; X7). The e-stop sequence in K18 runs on a stubbed
  Invoke-EmergencyStopInternal that never writes session.json, which is why the suite could not see X1.
- **N7 not run by me:** PowerShell 7 suites, any live Bay 1 or shell-process run (no live claim is made here).
- **N8 tool:** scripts/ops Test-AocDiffHygiene false-FAILs the added .ps1 lines as LF under `text eol=crlf` (R12 of the
  prior verdict; `git ls-files --eol`: `i/lf w/crlf attr/text eol=crlf` for both files).

## Checklist (aoc-verifier MUST-PASS)
1. Tree/branch: `git rev-parse --show-toplevel` = C:/aoc-wt/kiosk-rr1-r7-attack, branch verify/kiosk-rr1-r7 (at
   41ac9ec5); suites in C:/aoc-wt/kiosk-rr1-r7-attack-run (detached 41ac9ec5, `git status --ignored` clean). PASS.
2. Tier: Opus 5.5 verifier, Sonnet 5.5 builder, stated in the header. PASS.
3. Mutants: 11 runs (baseline + G1-G10), the builder's runner pointed at my worktree, copies only, each run finished with
   a RESULT line; baseline M00 365/0 SURVIVED; G1 354/11, G2 364/1, G3 364/1, G4 364/1, G5 364/1, G6 355/10, G7 364/1,
   G8 359/6, G9 364/1, G10 (mine: the handler passes no model) 359/6, each naming the expected test
   (`attack-verifier\mut\mut-results.txt`). No build step (PowerShell). G2, G4, G5, G9 die only on pure-gate asserts; the
   handler wiring is pinned by G8 and G10. PASS.
4. Suites: Windows PowerShell 5.1 (`System32\WindowsPowerShell\v1.0\powershell.exe`), clean detached checkout, all 14
   files exited on their own with a RESULT line: 227+131+72+365+27+63+71+34+55+13+201+21+28+70 = **1,378 passed, 0 failed**
   (base 097b3b5 per the prior verdict 1,360; +18 = the K18b assertions; builder 1,378/0). Summary
   `attack-verifier\suites\summary.txt`. PASS.
5. Layer: the class claim (a Reset never touches a running session) was attacked through the REAL Execute-Command, the
   REAL Invoke-EmergencyStopInternal and Clear-EmergencyStopInternal, and the shell's REAL Get-KioskLauncherWanted,
   Get-KioskLauncherAction and Get-KioskSessionGuard, lifted by AST from the branch files (Windows PowerShell 5.1). No live
   shell or Bay 1 run; none is claimed. PASS for what is claimed.
6/7. No money or identity write in the diff. The "who is playing" decision was attacked on every writer of the fact it
   reads (session.json status: Start, Prep, UpdateSessionDisplay, End, e-stop, Reset) and every input (payload force,
   baySessionId variants, session.json shapes, clock). PASS.
8. Control bytes: `git diff 097b3b5...41ac9ec5 | grep -cP '[\x00-\x08\x0b\x0c\x0e-\x1f]'` = 0; non-ASCII lines 0. PASS.
9. Server: n/a (no server).
10. Processes: none started besides PowerShell test hosts (each exited on its own). PASS.
11. Local reds: see 4. Base reds are the expected 6 (below).
12. Findings on disk, verdict on top, no "ruled/approved". PASS.

## Evidence
- **Diff (097b3b5...41ac9ec5):** `src/BayAgent/BayAgent.ps1` +34 (Get-ResetGate, one call at the top of the Reset handler)
  and `tests/BayAgent.Kiosk.Tests.ps1` +53/-1. The kiosk shell file, kiosk-policy.json, the e-stop handlers and every
  other command handler are untouched: the shell's OFF default, A0.457 and the e-stop path are unchanged. The only writer
  of status READY is the Reset handler (`git grep READY`); UpdateSessionDisplay can write any status a payload carries
  (pre-existing; nothing sends READY).
- **Fail on base for the right reason:** the branch's test file run against 097b3b5's BayAgent.ps1 plus Get-ResetGate's
  definition (present, not called, so the lift resolves): 359 passed, 6 failed, exactly: R7 skip/result, session.json
  byte-identical, no display/facility, other-session Reset, RR1 L3 ACTIVE, RR1 L3 shell held
  (`attack-verifier\base\kiosk-on-base.txt`).
- **Attack harness** (`attack-verifier\vx-block.ps1` spliced into a copy of the suite before K19; output
  `attack-verifier\vx-run-ps51.txt`, observations `attack-verifier\vx-observations.txt`; the suite still 365/0 around it):
  - X0 control: ACTIVE s-x0, cancel Reset: skipped, wall unchanged (the builder's case holds).
  - **X1** real e-stop: Start -> ACTIVE; engage -> STOP; clear -> still STOP (engaged=False; A0.457 keeps the game);
    cancel Reset: reset=True, display stop+start, facility Idle, wall READY.
  - **X1b** RR1 through STOP: P ended (closed P), Q's intent write held failing, Q ACTIVE: shell=held; e-stop
    engage+clear: wall STOP, shell=held; cancel Reset: wall READY, **shell verdict on Q's running launcher = close**.
  - **X2** A2 plays, B2's Prep (end minus 15) -> PREP/s-B2; B2's cancel Reset: reset=True, display stop+start, facility
    Idle, wall READY; A2's intent still wanted.
  - **X2b** RR1 through Prep with no Reset: A2b playing with a pending intent write: held; after B2b's Prep: PREP,
    **shell = close**.
  - **X3** B3 plays, A3's End claimed after B3's Start (both due at A3's end; the agent claims `createdon asc`) ->
    ENDED/s-A3 (launcher left alone: late_old_session_skip); any cancel Reset: reset=True, display, Idle, READY.
  - X4 ACTIVE with end 16 min ago: proceeds; 14 min ago: holds. X5-X10 as in the residuals.
  - In X1, X2 and X3 the wall had ALREADY lost the live countdown before the Reset (STOP after a clear, B's Prep, A's late
    ENDED; pre-existing writers); the Reset's added harm is the display restart, facility Idle and READY, which the shell
    treats as "nobody plays" (X1b).
- **Platform facts read (abg-member-web origin/main db9b477a):** cancel = cancel every Pending command of the session plus
  one Reset bound to that session (`build_BaySession@odata.bind`), payload `{"mode":"Full","reason":"BookingCanceled"}`,
  `build_notbefore = now`; Prep notBefore = start - 15, Start = start, Warn5 = end - 5, End = end; the extension's display
  update is best effort (`TryQueueDisplayAsync` logs and continues). The agent claims due commands `$orderby=createdon asc`.
- **Facility today:** Invoke-ProjectorPower and the audio driver are placeholders (`simulated=true`) and the shipped
  agent-config has facility disabled, so "facility Idle" is a plan until real drivers land; the wall rewrite and the
  display stop/start are real.

## New failure class (for the aoc-verifier skill; not written by me, per the brief)
- **A gate keyed on a status file that OTHER commands rewrite while the protected fact still holds** (kiosk Reset gate,
  2026-10-09; the 2026-10-08 "proxy" class one layer down). The fix moved "never touch a running session" from the intent
  to session.json's status, but Prep (end minus 15), a late End of the previous booking (claimed `createdon asc`), an
  emergency stop that was cleared (STOP persists) and a stale end each move that status off ACTIVE while a member still
  plays; the suite's e-stop was a stub that never wrote the file. For any gate on a shared status: list every writer of
  that status and every command that can arrive while the protected fact holds, and run each through the REAL handler
  (never a stub of the writer) before the gated command.
