# campaign-monitor

`campaign-monitor` is a terminal monitor for DST campaigns. It polls
`campaign status`, ranks what needs attention, and keeps a local history so
trends survive restarts. It only reads campaign state. To start a campaign,
see [`campaign-supervisor`](../campaign-supervisor/README.md).

```sh
cargo build --release -p campaign-monitor
export PATH="$PWD/target/release:$PATH"   # cargo build installs nothing
```

## Start watching

```sh
# On the campaign host
campaign-monitor --state /data/dst/state

# From another machine, over ssh (key auth; BatchMode is on)
campaign-monitor --state /data/dst/state --ssh dst-host --campaign '~/bin/campaign'

# A saved snapshot
campaign status --state /data/dst/state > snap.json
campaign-monitor --file snap.json
```

`--campaign` names the `campaign` binary on the host that runs it and
defaults to `campaign` on `PATH`. The monitor polls every 15 seconds
(`--interval`), and waits at least four times the last fetch between
polls. The header shows the snapshot age and turns `STALE` when the next
snapshot is overdue. Below 60x16 the monitor shows only the severity
counts and the worst signal.

`campaign-monitor --help` lists every option. Useful ones:

| Option | Effect |
| --- | --- |
| `--interval SECONDS` | least time between snapshots |
| `--timeout SECONDS` | kill a snapshot command after this long (default 300) |
| `--history PATH` / `--no-history` | where samples go; default `~/.local/state/campaign-monitor/HASH.jsonl` for `--state` |
| `--color never\|16\|256\|truecolor` | override color detection |
| `--ascii` | ASCII glyphs for consoles without Unicode |

## Tabs

| Key | Tab | Shows |
| --- | --- | --- |
| `1` | Overview | campaign facts, finished-attempt trend, outcomes by domain, top signals |
| `2` | Signals | ranked signals (critical, warning, info) and the selected one's detail |
| `3` | Profiles | profile-by-run matrix; each cell is the worst outcome of that run |
| `4` | Jobs | jobs, with the selected job's signals and attempts |
| `5` | Findings | failure groups, with copy-paste replay and dispose commands |

A signal's domain says where to look first: `service` (a checked property
failed), `simulator` (the worker or replay disagrees with itself),
`campaign` (supervisor records), `host` (cgroups, watchdog, disk), or
`chaos` (controller interruptions).

## Keys

Press `?` for the full list on the current tab.

| Key | Action |
| --- | --- |
| `j` `k`, `^d` `^u`, `gg` `G` | move, half screen, first and last row |
| `Tab` `S-Tab` | next, previous tab |
| `/`, `n` `N` | search; next, previous match |
| `Enter` | open the selected profile, signal, or failure group as a job list |
| `^o` | back |
| `Esc` | clear the search, then the drill-down |
| `f` | Jobs: cycle the filter (problems, all, unsettled) |
| `h` `l` | Profiles: older, newer runs |
| `y` | copy to the clipboard (see below) |
| `r` | fetch a snapshot now |
| `p` | pause; snapshots are still fetched and shown on resume |
| `q` | quit |

`y` copies with OSC 52, so it works over ssh in terminals that support it.
It copies the job id on Jobs, the profile name on Profiles, the signal's
subjects on Signals, and the replay command for the target finding on
Findings.

## Triage from the monitor

1. Open Findings (`5`) and select a failure group.
2. Press `y` to copy its replay command:
   `campaign triage --state … --cgroup-root "${CAMPAIGN_CGROUP_ROOT:?}" --from-run <id> --step replay`.
3. Run it in the delegated shell on the campaign host once `dispatch` has
   exited; `triage` needs the state directory's lock.
4. Record the decision with the `dispose` command the pane shows.

## Scripted checks

`check` fetches one snapshot, prints its signals, and exits by the worst
one. Use it in cron or CI.

```sh
campaign-monitor check --state /data/dst/state          # text
campaign-monitor check --state /data/dst/state --json   # one JSON object
```

| Exit | Meaning |
| --- | --- |
| 0 | nothing above info |
| 1 | a warning |
| 2 | a critical signal |
| 3 | the snapshot failed |
| 4 | the history file is unusable |
| 5 | `watch` lost its terminal or poller |
| 64 | usage error |
| 128 + signal | `watch` stopped by `SIGHUP` (129), `SIGINT` (130) or `SIGTERM` (143) |
