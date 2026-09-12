# ndjson contract v1 (`cage/1`)

curam-run speaks one request per line on stdin, one result per line on
stdout. The contract is transport-agnostic: any consumer that speaks this
schema can drive the cage (T6 property — replayable without curam's code).

## Request

```json
{
  "id": 1,
  "v": "cage/1",
  "cmd": ["bash", "-c", "cat /etc/passwd"],
  "cwd": "/home/x/project",
  "timeout_s": 30,
  "net": false,
  "geo": "RU",
  "bind": ["/home/x/project:/home/x/project", "/home/x:/home/x"],
  "allow_hosts": ["github.com"],
  "deny_hosts": ["evil.example"]
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | int | echoed on the result; closes the request |
| `v` | string | envelope version, must be `cage/1`; anything else is rejected |
| `cmd` | `[string]` | argv of the command, executed inside the cage |
| `cwd` | string? | working directory inside the cage |
| `timeout_s` | int? | kill the cage after this many seconds; result gets `timed_out: true` |
| `net` | bool | `false` → egress denied (`--unshare-net`); `true` → host netns |
| `geo` | string? | ISO-3166 country code; loads `<lists>/geo/<CODE>/list.json` CIDRs into the cage's own netns via nftables and drops egress to them (e01s07) |
| `bind` | `[string]` | writable `host:guest` mounts into the cage (e.g. the harness workdir + HOME so git/pip/cargo work); default empty |
| `allow_hosts` | `[string]` | hostname suffix allowlist → `host_allow` verdicts |
| `deny_hosts` | `[string]` | hostname suffix denylist → `host_deny` verdicts (deny beats allow) |

## Result

```json
{
  "id": 1,
  "exit": 0,
  "stdout": "...",
  "stderr": "",
  "timed_out": false,
  "cages": ["bwrap:unshare-net", "bwrap:ro-system", "nft:geo:RU"],
  "verdicts": [
    {"action": "deny", "rule_id": "host_deny", "source": "deny list",
     "source_hash": "cage/1", "evidence": "evil.example"}
  ]
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | int | echoes the request id |
| `exit` | int | child exit code (1 if killed by timeout) |
| `stdout` / `stderr` | string | captured output |
| `timed_out` | bool | true when the cage was killed on `timeout_s` |
| `cages` | `[string]` | layers applied: `bwrap:unshare-net`, `bwrap:ro-system`, `bwrap:net-on`, `nft:geo:<CODE>` |
| `verdicts` | `[object]` | the provable chain `{action, rule_id, source, source_hash, evidence}` |

Errors (bad envelope, unreadable geo list) come back as a single-line
`{"id":…, "error": "…"}` result.

## Geo (e01s07)

`geo: "RU"` makes curam-run:

1. read `<lists>/geo/RU/list.json` — the verified lists pipeline schema
   (`{rev, entries}`) where `entries` are CIDR strings;
2. render an nftables ruleset: `table inet geo_RU` with an
   interval-set `country` of those CIDRs and a `output` hook chain that
   drops `ip daddr @country`;
3. bind the ruleset read-only into the cage (`/cage-geo.rules`), add
   `CAP_SYS_ADMIN` + `CAP_NET_ADMIN` + `CAP_NET_RAW`, keep the parent
   netns, and run the command under `unshare -n` — so the rules land in
   the cage-*owned* netns where the caps apply (the bwrap `--unshare-net`
   netns is parent-owned and would reject nft).

Egress stays denied: the fresh netns has only loopback. The country set
is kernel-enforced at the connection — no TOCTOU, no resolver involvement.
Data licensing: only permissive CIDR sources (ipdeny / ipverse / DB-IP
Lite CC BY 4.0); no GeoLite2 in the repo.
