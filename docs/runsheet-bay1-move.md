# Run sheet: move Bay 1 from C:\AllBirdies to C:\AceOfClubs (and back if needed)

Tool: `src/BayAgent/tools/Move-BayInstall.ps1` (Plan, Move, Verify, Back). Proof: `tests/BayAgent.MoveInstall.Tests.ps1`.
Who: Kevin, at Bay 1. Time: 45 to 60 minutes, including one restart. Sitting: FLEET-REL in the rename plan.

**The Expect lines below were copied from the tool's console in the suite's run on a modeled bay**
(`C:\aoc-wt\verdicts\rename-fleet-b-evidence\run10\console-*.txt`, with the test folder replaced by the bay's
paths). They have not been seen on a real bay yet. Values that differ on Bay 1 are in angle brackets: `<version>` (the
FLEET-A release), `<thumbprint>` (Bay 1's code-signing certificate), `<PC>` (the computer name), `<n>` (a session
number), `<stamp>` (the time of the run).

## What "moved" means (the tool checks every item before it says MOVED)

| Item | How the tool does it | Checked by |
|---|---|---|
| Both folders, BayAgent and SessionDisplay (the wall's Edge profile is inside SessionDisplay) | a rename on the same disk; no file is opened, the secret file included | names, sizes, times and access rules equal before and after; the secret folder's own rules checked separately |
| `BayAgent\current` if it is a link | re-pointed into the new folder | no link points into the old folder |
| The bootstrap scripts | ABG.\* replaced by the release's AOC.\* files, signed on the bay with Bay 1's own certificate and timestamped; the old files are kept in the journal | signer equals the certificate that signed the old files; the old names are gone |
| `agent-config.json` | only the values that name the old folder are rewritten (five on today's file); its byte-order mark is kept | every other value unchanged; no value names the old folder |
| The two scheduled tasks | `\ABG Bay Agent` and `\ABG Host Watchdog` become `\AOC Bay Agent` and `\AOC Host Watchdog`, same definition except the paths and names, same account and sign-in kind; the old ones removed (their definitions kept in the journal) | no task on the PC names the old folder; the new tasks exist, are enabled, and start files that exist |
| The Winlogon Shell (HKLM) | rewritten only if it names the old folder | it no longer does |
| The old folder | removed only if it is empty | |
| After the restart (Verify) | | the tasks are Ready, AgentHost and BayAgent.ps1 run from the new folder, `state\agent-alive.json` was written since the restart, nothing runs from the old folder |
| A way back | any failure during Move puts back every step already done (exit 2); `-Mode Back` reverses a finished Move from its journal | the suite fails each stage on purpose and compares the bay byte for byte |

## Before the sitting (not at the bay)

| # | What | Who | Done when |
|---|---|---|---|
| P1 | The FLEET-A release (the agent and bootstrap that take their folder from where they are installed) is published, and the fleet attack has passed. `<version>` is ABOVE 1.6.1 (Bay 1 runs a 1.6.1 that still looks for `C:\AllBirdies`; the move's version check could not tell the two apart): see `runsheet-fleet-release.md`, all of it, in order | orchestrator, Kevin | release `<version>` exists at the new repository address |
| P2 | Bay 1 is updated to `<version>` **at the old folder** with the ordinary Update BayAgent command, and the update guard has finished | orchestrator, Dev | Bay 1 reports `<version>`; on the bay `C:\AllBirdies\BayAgent\state\update-pending.done.json` exists and `update-pending.json` does not |
| P3 | The plugin's release guard and the `build_fleetrelease_ops` address check accept the tool path under **both** folders, deployed in Dev | portal slice | a read of the deployed check |
| P4 | **All six** of the release's new bootstrap files `AOC.AgentHost.ps1`, `AOC.HostWatchdog.ps1`, `AOC.LauncherShell.ps1`, `AOC.ReleaseFinalize.ps1`, `AOC.RotateClientSecretDpapiAndTest.ps1`, `AOC.SetClientSecretDpapi.ps1` (none carries a signature block; the tool signs each on the bay) are on a USB stick in a folder `bootstrap`, with `Move-BayInstall.ps1` beside it. The tool stages the new counterpart of EVERY `ABG.*` file it finds in Bay 1's `bootstrap\`, so a stick with three files makes Move refuse at staging (exit 1, nothing changed) if Bay 1 holds `ABG.ReleaseFinalize.ps1` or `ABG.SetClientSecretDpapi.ps1` | orchestrator | the stick holds `Move-BayInstall.ps1` and the six `bootstrap\AOC.*.ps1` (step R6 of `runsheet-fleet-release.md`) |
| P5 | No session is running or booked at Bay 1 for the next hour | Kevin | |
| P6 | Kevin has BayKiosk's password at hand (needed only if Plan says "needs its password") | Kevin | |

Nothing in Dev changes before the move. The three command templates change right after it (step 9).

## At the bay

**1. Sign in as the administrator with Switch user** (leave BayKiosk signed in: the tool reads BayKiosk's own
settings while it is signed in, and signs it out itself during the move).

**2. Copy the tool** from the stick to `C:\BayMove` (the folder must not be inside `C:\AllBirdies` or
`C:\AceOfClubs`): `C:\BayMove\Move-BayInstall.ps1` and `C:\BayMove\bootstrap\AOC.*.ps1`.

Then make `C:\BayMove` administrator-only, in the administrator window: `icacls C:\BayMove /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F"`, and check with `icacls C:\BayMove` that only those two are listed. The tool signs the files in `-BootstrapSource` with the bay's certificate and refuses a folder that standard users can write (and a folder above it that they can delete from or change); `C:\` gives Authenticated Users Modify on every new folder under it, so without this step Plan says `REFUSED: -BootstrapSource is not admin-only`. The same judgment is made of the new root, the journal folder, and every folder above them (a junction anywhere on a path is refused): Plan prints any such finding with the folder named, so it is safe to run first.

**3. Open Windows PowerShell as administrator** and run Plan (it changes nothing):

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\BayMove\Move-BayInstall.ps1 -Mode Plan -ExpectAgentVersion <version> -BootstrapSource C:\BayMove\bootstrap
```

Expect (copied from the modeled run):

```
Move-BayInstall 1.0.0  mode Plan  old root C:\AllBirdies  new root C:\AceOfClubs

== Plan: Move from C:\AllBirdies to C:\AceOfClubs
  installed agent version: <version>
  move folder   C:\AllBirdies\BayAgent -> C:\AceOfClubs\BayAgent
  move folder   C:\AllBirdies\SessionDisplay -> C:\AceOfClubs\SessionDisplay
  re-point link BayAgent\current: C:\AllBirdies\BayAgent\releases\<version> -> C:\AceOfClubs\BayAgent\releases\<version>
  bootstrap     ABG.AgentHost.ps1 -> AOC.AgentHost.ps1
  bootstrap     ABG.HostWatchdog.ps1 -> AOC.HostWatchdog.ps1
  bootstrap     ABG.LauncherShell.ps1 -> AOC.LauncherShell.ps1
  signer        <thumbprint> (LocalMachine\My)
  task          \ABG Bay Agent -> \AOC Bay Agent (account <PC>\BayKiosk, needs its password)
  task          \ABG Host Watchdog -> \AOC Host Watchdog (account S-1-5-18)
  config        .clientSecretDpapiPath: C:\AllBirdies\BayAgent\secrets\clientsecret.dpapi -> C:\AceOfClubs\BayAgent\secrets\clientsecret.dpapi
  config        .sessionJsonPath: C:\AllBirdies\SessionDisplay\data\session.json -> C:\AceOfClubs\SessionDisplay\data\session.json
  config        .sessionDisplay.url: file:///C:/AllBirdies/SessionDisplay/current/index.html -> file:///C:/AceOfClubs/SessionDisplay/current/index.html
  config        .sessionDisplay.profileDir: C:\AllBirdies\SessionDisplay\edge-profile -> C:\AceOfClubs\SessionDisplay\edge-profile
  config        .kiosk.shell: C:\AllBirdies\BayAgent\bootstrap\ABG.LauncherShell.ps1 -> C:\AceOfClubs\BayAgent\bootstrap\AOC.LauncherShell.ps1
  Winlogon Shell: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -WindowStyle Hidden -File "C:\AllBirdies\BayAgent\bootstrap\ABG.LauncherShell.ps1" -> ...AOC.LauncherShell.ps1"
  BayKiosk sessions to sign out: 1
RESULT: Move would proceed (nothing was changed)
```

Lines that may differ and are fine: no `re-point link` line (Bay 1's `current` is a real folder after any update
since 1.3.1); no `Winlogon Shell` line (Bay 1 runs Explorer as its shell); `(account ..., needs its password)` absent
from the agent task (it then signs in with the interactive token and nothing asks for a password); `Note:` lines.

**Stop and photograph the screen if** it ends `RESULT: REFUSED`. Each refusal names its reason; what was seen in the
suite:

```
  REFUSED: the installed agent is '<installed>' (current\manifest.json), not '<version>': install that release at the old root first
  REFUSED: an update is in flight or still being watched (state\update-pending.json phase 'promoted'); wait for its guard to finish
  REFUSED: BayKiosk's own Shell value starts a file under C:\AllBirdies; this tool does not edit an account's own registry
RESULT: REFUSED; nothing on the bay was changed
```

Also stop if a `Note:` says BayKiosk is not signed in (go back to step 1), or names a task, Run entry or Startup item
that starts something under `C:\AllBirdies` that the sheet did not expect.

**4. Run Move.** Same command with `-Mode Move`. It stages and signs the new bootstrap files first (nothing on the bay
changes yet), then asks you to type `MOVE`, then BayKiosk's password if the plan said "needs its password". BayKiosk is
signed out during the move; the wall goes dark.

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\BayMove\Move-BayInstall.ps1 -Mode Move -ExpectAgentVersion <version> -BootstrapSource C:\BayMove\bootstrap
```

Expect, after the plan above (copied from the modeled run):

```
== Stage the bootstrap files (nothing on the bay changes yet)
  ready: AOC.AgentHost.ps1 (signed by <thumbprint>, timestamped)
  ready: AOC.HostWatchdog.ps1 (signed by <thumbprint>, timestamped)
  ready: AOC.LauncherShell.ps1 (signed by <thumbprint>, timestamped)

== 1. register the new tasks, disabled
  registered \AOC Bay Agent (disabled)
  registered \AOC Host Watchdog (disabled)

== 2. stop the bay
  disabled and ended \ABG Bay Agent
  disabled and ended \ABG Host Watchdog
  signing out BayKiosk (session <n>)
  nothing runs from the old root

== 3. move the folders
  created C:\AceOfClubs with the access rules of C:\AllBirdies
  moved C:\AllBirdies\BayAgent -> C:\AceOfClubs\BayAgent
  moved C:\AllBirdies\SessionDisplay -> C:\AceOfClubs\SessionDisplay

== 4. links, bootstrap files, configuration, Winlogon
  link C:\AceOfClubs\BayAgent\current -> C:\AceOfClubs\BayAgent\releases\<version>
  bootstrap\ABG.AgentHost.ps1 -> bootstrap\AOC.AgentHost.ps1 (the old file is kept in the journal)
  bootstrap\ABG.HostWatchdog.ps1 -> bootstrap\AOC.HostWatchdog.ps1 (the old file is kept in the journal)
  bootstrap\ABG.LauncherShell.ps1 -> bootstrap\AOC.LauncherShell.ps1 (the old file is kept in the journal)
  agent-config.json: 5 value(s) now name C:\AceOfClubs
  Winlogon Shell -> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -WindowStyle Hidden -File "C:\AceOfClubs\BayAgent\bootstrap\AOC.LauncherShell.ps1"

== 5. the tasks
  enabled \AOC Bay Agent
  enabled \AOC Host Watchdog
  removed \ABG Bay Agent (its definition is kept in the journal)
  removed \ABG Host Watchdog (its definition is kept in the journal)

== 6. the old root
  removed C:\AllBirdies (it was empty)

== 7. check every item of done
  every item holds

== 8. start allowed again
  removed stop.host

RESULT: MOVED to C:\AceOfClubs. Journal: C:\ProgramData\AceOfClubs\BayMove\<stamp>-move
Restart the PC now; after BayKiosk signs in, run this tool with -Mode Verify.
```

The `link` and `Winlogon Shell` lines appear only if Plan listed them. If `C:\AllBirdies` holds anything else, step 6
says it was kept; that is fine.

**If it ends `RESULT: FAILED and everything was put back`** (exit 2): the bay is as it was before step 4. Photograph
the `FAILED:` line, restart the PC, and hand the photo back. Two failures seen in the suite:

```
FAILED: registering the task 'AOC Bay Agent' failed: The user name or password is incorrect. (8,44):UserId:
FAILED: 1 process(es) still use C:\AllBirdies after 120 s; close them and run Move again
```

The first means the password was mistyped; run step 4 again. The second lists the program above it (`still running: ...`);
close it and run step 4 again. The tool stops only the bay program's own PowerShell and Edge, by their process ids.

**If it ends `RESULT: FAILED and <n> step(s) could NOT be put back`** (exit 3): do not restart. Photograph the
`COULD NOT put back:` lines and the journal folder name, and hand them back. The journal folder holds the old task
definitions, the old bootstrap files and the old `agent-config.json`.

**5. Restart the PC.** BayKiosk signs in by itself.

**6. Look at the wall.** It shows the session display as before (the same Edge profile, now under
`C:\AceOfClubs\SessionDisplay\edge-profile`). The suite cannot prove this: Edge is not run by it.

**7. Run Verify** as the administrator (Switch user again, leave BayKiosk signed in), about two minutes after the
restart:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\BayMove\Move-BayInstall.ps1 -Mode Verify
```

Expect (copied from the modeled run, after a modeled restart):

```
== Verify: the install is at C:\AceOfClubs
  ok: the task \AOC Bay Agent is Ready
  ok: the task \AOC Host Watchdog is Ready
  ok: BayAgent.ps1 runs from the new root (process <id>)
  ok: AgentHost runs from the new root (process <id>)
  ok: state\agent-alive.json written since the last start
RESULT: VERIFIED
```

`\AOC Bay Agent` may read `Running` instead of `Ready`. If it says `RESULT: NOT VERIFIED` with
`NOT OK: no BayAgent.ps1 runs ...`, wait two more minutes and run it again (seen in the suite before the restart).

**8. Read Bay 1 in Dev** (orchestrator): its next heartbeat arrives, and it reports `<version>`.

## Right after the move (Dev, orchestrator)

**9.** The three command templates name the tool under the old folder (named-column read, 2026-10-14 09:27Z,
`build_commandtemplates.build_defaultpayloadjson`): "Update BayAgent" (`20bf8239-b038-f111-88b5-6045bd0755da`),
"Update SessionDisplay" (`21bf8239-...`), "Update PromosPack" (`22bf8239-...`), each
`C:\\AllBirdies\\BayAgent\\tools\\Update-<name>.ps1`. After the move, Bay 1's agent refuses a command that starts a
file outside its own folder, so these three change to `C:\\AceOfClubs\\...` before the next update is sent to Bay 1,
and only once P3 is deployed. No settings row and no environment variable names the folder (same read). That write
is not part of this sheet.

## The way back

- **During Move:** automatic (exit 2), see step 4.
- **After a finished Move:** run Back as the administrator. It reads the newest Move journal, asks you to type `BACK`
  and the password if needed, and reverses every step: the folders, the link, the ABG.\* bootstrap files from the
  journal (their original signatures), `agent-config.json` (byte for byte, as the suite proves), the two ABG tasks,
  the Winlogon Shell. A failed Move's journal is skipped; Back takes the newest COMPLETED Move. Then restart and run
  Verify with the same command as step 7: it finds which folder the install is in and checks that one (the suite saw
  `RESULT: MOVED to C:\AllBirdies` from Back, then the original tasks and files byte for byte).

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\BayMove\Move-BayInstall.ps1 -Mode Back -ExpectAgentVersion <version>
```

  If the three templates were already changed (step 9), change them back too.

## The fallback if neither Move nor Back can finish

A blank setup at the new folder with the FLEET-A release's setup script. It is not a repair over the existing
install: the old tasks must be removed first (else two agents run), and `state\credential.json` (the bay's identity)
and `agent-config.json` must be carried over by hand or the bay enrolled again. See the FLEET-B report, section 7.
