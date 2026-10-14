# Run sheet: the rename release (FLEET-REL)

Where it sits: this is the release half of the rename. It comes BEFORE `runsheet-bay1-move.md` (that sheet's P1 to P4 are
steps R1 to R6 here). Source: section 6 of the fleet attack, `C:\aoc-wt\verdicts\rename-fleet-attack-2026-10-14.md`
(FLEET-A `765bd4f9` and FLEET-B `b39dc364`, both judged MERGE), on the integration branch
`integrate/rename-fleet-2026-10-14`. Nothing here has been run: the branch was built and tested offline.

**Steps marked KEVIN are not done without Kevin's word:** the repository rename (R3), the merge of the fleet branch to
`main` (R3), and publishing the release asset (R5). The orchestrator does the rest.

**Order matters, and the order is the sheet.** R1 comes first because the version is what the move's safety check reads.
R2 comes before R3 because the Dev guard must accept the new repository name before any command or release row carries it.
R3 and R4 are one sitting. R5 comes after R3 so the asset address is born at the new name. Do not start the next step
until the "Done when" of the one before reads true.

## What is already done in the branch (do not redo)

- The two slices are merged, and the assembled tree is green (every suite at both roots; the hand-over has the table).
- The six stale embedded signature blocks are stripped (K3): `src/BayAgent/RestartBayAgent.ps1`,
  `src/BayAgent/bootstrap/AOC.AgentHost.ps1`, `AOC.HostWatchdog.ps1`, `AOC.ReleaseFinalize.ps1`,
  `src/BayAgent/tools/Update-SessionDisplay.ps1`, `Update-PromosPack.ps1`. Every delivery path signs on arrival
  (Update-BayAgent signs every `.ps1` under `releases\<v>` before promotion; Day0 signs the bootstrap and the updaters; the
  move tool signs each staged bootstrap file with the bay's own certificate). Do not "re-sign in the repository".
- The bay's own command check is the plugin's closed allowlist (K1), with its own suite `tests/BayAgent.CommandCheck.Tests.ps1`.
  It gets its own attack before the release; R1 does not start until that verdict is MERGE.

## Steps

| # | What | Who | Done when |
|---|---|---|---|
| R1 | **Bump the version above 1.6.1** in one release-prep commit on the integration branch (details below) | orchestrator | `tools\Build-ReleasePackage.ps1 -Version <version>` runs to its end (it refuses a mismatch) and every suite passes at both roots |
| R2 | **Deploy the dual-name plugin in Dev, before any command or release row names the new repository or folder.** `GuardFleetReleasePlugin.FleetRepos = { "aoc-fleet-updates", "abg-fleet-updates" }` and `GuardBayCommandPlugin.AgentBaseDirs` with both bay folders. They are on `fix/rename-plug-f1d-2026-10-14` and NOT on the portal working branch, which still holds the single `FleetRepo = "abg-fleet-updates"` | orchestrator, Dev | a read of the deployed plugin (or its behavior: a release row naming `aoc-fleet-updates` saves, one naming another repository is refused) |
| R3 | **KEVIN: rename the repository `abg-fleet-updates` to `aoc-fleet-updates` in GitHub, and merge the fleet integration branch to `main`, back to back.** Nothing else runs between the two: no blank-PC setup, no command. The new Setup-BayPC names `raw.githubusercontent.com/millwright-works/aoc-fleet-updates/main/...` and `tools/AOC-Day0-Setup.ps1`, and those 404 until both halves are done; an older Setup copy names `abg-fleet-updates/.../tools/ABG-Day0-Setup.ps1`, which 404s from the merge on whatever the redirect does, because the file is renamed | Kevin (the rename and the merge), orchestrator (the commands) | both halves done in one sitting; R4 is read at once |
| R4 | **Read both raw addresses for 200 before any setup runs** (below) | orchestrator | both print `200` |
| R5 | **KEVIN: publish the release asset after the rename**, from the merged tree, so its address is `https://github.com/millwright-works/aoc-fleet-updates/releases/download/<tag>/BayAgent-<version>.zip`. Do not rely on a redirect from the old name | Kevin (the publish), orchestrator (the build) | the asset address returns 200 and its SHA-256 equals the build's (below) |
| R6 | **Put all six `AOC.*` bootstrap files on the USB stick**, not three, with `Move-BayInstall.ps1` beside them (below) | orchestrator | the stick lists the six names, each equal to the merged tree's file |
| R7 | The move itself: `runsheet-bay1-move.md`, P2 to P6 and the sitting. Its step 9 (the three Dev command templates) comes right after it | orchestrator, Kevin | that sheet's own "done when" |

## R1: the version bump, in detail

FLEET-A is labeled 1.6.1, which Bay 1 already runs, and 1.6.1 as it runs today looks for `C:\AllBirdies`. The move tool's
only check that the installed agent derives its root is `current\manifest.json`'s version equal to `-ExpectAgentVersion`.
With 1.6.1 that check passes on a bay still running the OLD hardcoded agent; after Move and the restart that agent would
look for `C:\AllBirdies` and not start (Verify would catch it, with Kevin at the bay). So the release carries a number
above 1.6.1, and `<version>` in the move sheet's Plan, Move, Back and Verify lines and in P1 and P2 is that number.

The number is the orchestrator's choice (the Move suite models its bay with 1.7.0; any number above 1.6.1 works if it is
used everywhere). Change, in one commit:

1. `src/BayAgent/BayAgent.ps1`: the one line `$AgentCodeVersion = "<version>"` (line 334 today).
2. `src/BayAgent/kiosk/AOC.KioskShell.ps1`: the one line `$KioskShellCodeVersion = "<version>"` (line 79 today).
3. `src/BayAgent/manifest.json`: `version` and `releasedUtc`.
4. The test literals that pin them: `tests/BayAgent.Day0Enroll.Tests.ps1` (the assertion that reads `$AgentCodeVersion = "1.6.1"`,
   near line 1171) and `tests/BayAgent.KioskPackage.Tests.ps1` (the default `$version` of `Invoke-Build`, the literal in the
   mutant that rewrites `$KioskShellCodeVersion`, and the messages that say 1.6.1).
5. Read back: `git grep -n "1\.6\.1"` lists only history (comments about the 1.6.1 re-check, the Setup-BayPC "older than
   1.6.1" advice, which is correct as written) and no pin.

The suites that model a release at 1.6.1 inside a sandbox (InstallRoot's folders, Launch) name it as data, not as the
shipped version; leave them.

## R4: the two raw addresses

Read each; a 200 on both is the condition. From any PC with PowerShell (nothing here changes anything):

```
(Invoke-WebRequest -UseBasicParsing -Method Head -Uri https://raw.githubusercontent.com/millwright-works/aoc-fleet-updates/main/tools/AOC-Day0-Setup.ps1).StatusCode
(Invoke-WebRequest -UseBasicParsing -Method Head -Uri https://raw.githubusercontent.com/millwright-works/aoc-fleet-updates/main/src/BayAgent/bootstrap/AOC.AgentHost.ps1).StatusCode
```

If either is not 200, stop: no blank-PC setup runs, and the orchestrator reports to Kevin what was read. Whether raw
addresses redirect after a rename is not documented, so a 200 here is read, never assumed.

## R5: building and checking the asset

Build from the MERGED tree (not from the integration branch before the merge), after the rename:

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\Build-ReleasePackage.ps1 -Version <version>
```

It does not sign before zipping (its header says why: signing would change the SHA-256). The zip name is
`BayAgent-<version>.zip` under `dist\`. After Kevin publishes it, read the asset address for 200, download it, and compare
its SHA-256 with the build's. The three Dev command templates and the Fleet Release row use that address and that SHA-256.

## R6: the stick

`bootstrap\` on the stick holds exactly: `AOC.AgentHost.ps1`, `AOC.HostWatchdog.ps1`, `AOC.LauncherShell.ps1`,
`AOC.ReleaseFinalize.ps1`, `AOC.RotateClientSecretDpapiAndTest.ps1`, `AOC.SetClientSecretDpapi.ps1`, copied from
`src/BayAgent/bootstrap/` of the merged tree, and `Move-BayInstall.ps1` (from `src/BayAgent/tools/`) beside the folder.
The move tool stages the new counterpart of EVERY mapped `ABG.*` file it finds in Bay 1's `bootstrap\`. If Bay 1 holds
`ABG.SetClientSecretDpapi.ps1` (Day0's secret path places it) or `ABG.ReleaseFinalize.ps1`, a three-file stick makes Move
refuse at staging: exit 1, nothing changed, but the sitting stalls. Plan does not stage, so Plan says "would proceed" first.
Which `ABG.*` files Bay 1 holds is not established; six files cover every case.

## Not established (read before relying on this sheet)

- Anything on a real bay: logon, Task Scheduler starting the moved tasks, signing with Bay 1's certificate, a real restart
  and Verify.
- Whether raw.githubusercontent.com and release-asset addresses redirect after a rename (not documented).
- Which `ABG.*` bootstrap files Bay 1 holds, whether `RestartBayAgent.ps1` is on Bay 1 and where, whether any bay trusts
  the old `CN=ABG BayAgent Code Signing` certificate.
- Whether any caller can create a `build_baycommand` row with plugin execution bypassed (the bay's own check no longer
  depends on the answer, K1).
