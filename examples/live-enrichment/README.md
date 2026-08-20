# Live enrichment verification (2026-08-20)

The first run of the enrichment stack against **real providers**. Items 5, 6, and 7 had
until now been verified only offline, against fakes — including, for item 7, a URLhaus
response shape that was my own fixture agreeing with itself. This closes that gap for
items 6 and 7 and for item 5's cache, and is explicit about the one part it does not.

It found one real defect, described below.

## What was run

```bash
uv run case-analyzer examples/live-enrichment/case.json \
  --dry-run --enrich --allow-enrichment-in-dry-run --no-cache \
  --enrichment-limit 20 --enrichment-budget 120
```

`--dry-run` with `--allow-enrichment-in-dry-run` contacts enrichment providers while
skipping the LLM, so this measures enrichment in isolation and costs no model tokens.

[`case.json`](case.json) is **synthetic**. Enrichment discloses every observable to a
third party, so a real export would have leaked customer IOCs; each value here is public
and chosen for what it tests. The recorded enrichment block is
[`enrichment-2026-08-20.json`](enrichment-2026-08-20.json).

Providers reached: Cloudflare DNS, the RDAP registries, AbuseIPDB, and URLhaus.
**VirusTotal was not contacted** — `VIRUSTOTAL_API_KEY` is commented out in `.env`.

## Item 6 — UTS #46 confirmed, by a test that could have failed

The sharpest available check. Both readings of a sharp-s domain exist as *separate real
domains*, resolving to different addresses:

| Case wrote | UTS #46 non-transitional | IDNA2003 / transitional |
|---|---|---|
| `straße.de` | `xn--strae-oqa.de` | `strasse.de` |
| `faß.de` | `xn--fa-hia.de` | `fass.de` |

Live DNS therefore discriminates the two standards rather than merely accepting either.
The run produced `xn--strae-oqa.de` and `xn--fa-hia.de`, and both resolved. The
implementation is non-transitional UTS #46, as claimed.

Mixed case and a trailing dot also normalized as intended: `BÜCHER.de.` and `München.DE`
grouped onto `xn--bcher-kva.de` and `xn--mnchen-3ya.de`, with the original spellings kept
in `unicode_values`.

## Item 5 — cache confirmed, pacing not exercised

Two consecutive runs against a fresh `--cache-dir`:

| Run | Summary line | Wall |
|---|---|---|
| 1 | `found=6 … cached=0` | 3.65s |
| 2 | `found=6 … cached=6` | 2.69s |

The second run served all six provider answers from disk. `retrieved_at` on a cached
observation replays the **original** fetch time rather than the replay time, so a stale
answer stays visibly stale — the property that actually matters for an analyst reading a
report.

**Pacing was not exercised.** The only paced provider is VirusTotal, at one request per
15 seconds, and `VIRUSTOTAL_API_KEY` is commented out in `.env`. That code path has still
never run live. URLhaus is deliberately unpaced — abuse.ch publishes a fair-use policy
rather than a rate — so adding it does not exercise the pacer either.

## Item 7 — URLhaus confirmed against the real API

The part that most needed this: URLhaus answers **HTTP 200 for a refused query as well as
a hit**, so the outcome has to be read from `query_status`. That was implemented against a
fixture I wrote myself. Probing the real endpoint directly:

| Probe | HTTP | `query_status` | `_urlhaus_lookup` returned |
|---|---|---|---|
| URL listed by URLhaus | 200 | `ok` | `found` |
| URL not listed | 200 | `no_results` | `not_found` |
| Malformed URL | 200 | `invalid_url` | `error` |
| Empty string | 200 | `invalid_url` | `error` |

All four are HTTP 200. Reading the status code instead would have reported the malformed
and empty queries as hits. The implementation needed no change.

Two further details held up against real data. The reduced `payload_signatures` list is
deduplicated while `payload_count` counts every payload, and the live record has one
payload whose `signature` is `null` — so `payload_count: 1` with `payload_signatures: []`
is the documented asymmetry, now confirmed rather than asserted. And the case wrote the
URL with an **uppercase scheme**, `HTTP://42.178.23.194:35659/bin.sh`; normalization
lowercased the scheme, preserved the non-default port and the path, and URLhaus still
matched the result — so the normalization produces a form the provider accepts.

### Why a URL and its host are separate observables

The clearest evidence for item 7's central design decision came out of one field:

| Observable | Provider | Answer |
|---|---|---|
| `http://42.178.23.194:35659/bin.sh` | URLhaus | `malware_download`, online, Mozi ELF/MIPS payload |
| `42.178.23.194` (`#host`) | AbuseIPDB | confidence score **3**, 1 report |
| `42.178.23.194` (`#host`) | RDAP | China Unicom Liaoning, allocated portable |

Before item 7 the URL field contributed only its host, so this case would have been
enriched to "an ordinary consumer ISP address with a near-zero abuse score" — benign
looking. The malice is in the path, and only the URL lookup sees it. This is the scenario
the design was argued from, now observed rather than hypothesised.

Also confirmed live: the email address was recorded and sent to no provider, the private
address `10.42.0.7` drew no reputation lookup, and `8.8.8.8` reached both RDAP and
AbuseIPDB.

## The defect this found

A URL's userinfo was stripped from the value sent to providers and written to the cache —
that part worked. But `unicode_form` was populated from the **raw** candidate, so the
password came back in `unicode_values`, which is recorded in the report and included in
the payload sent to the model. The observed output was:

```
value          = https://xn--bcher-kva.de/Katalog/Suche.php?q=1#frag
unicode_values = ['HTTPS://Admin:hunter2@Bücher.DE:443/Katalog/Suche.php?q=1#frag']
```

No offline test caught this because `unicode_form` is empty for an ASCII URL: the leak
required a URL that was internationalized *and* credential-bearing, a combination none of
the fixtures had. The same raw candidate was also returned as `value` on the
invalid-URL branches, so an unusable URL kept its secret too.

Fixed by `_without_userinfo`, applied before any branch returns. It splices rather than
rebuilds, so the original scheme case and host spelling survive for the analyst, and it
keys off `parts.netloc` — which ends at the first `/`, `?`, or `#` — so an `@` inside a
query string is not mistaken for a credential. Four tests cover it; two of them fail
against the previous code.

After the fix, `unicode_values` reads
`['HTTPS://Bücher.DE:443/Katalog/Suche.php?q=1#frag']`.

## Known and out of scope

The credential still appears once in the output, under
`source_data.child_containers[0].artifacts[2].cef.requestURL` — the case export echoed
back as written. That is pre-existing behaviour of `source_data` and not something this
change introduced, but it is worth stating plainly: **a case export containing a
credential still sends it to the model.** Anyone handling exports with embedded secrets
should know that. It is adjacent to plan item 10, which proposes sending only the source
fields the normalizer did not already lift.

## The VirusTotal run — pacer confirmed, URL identifier still not

A second run with `VIRUSTOTAL_API_KEY` enabled is recorded separately in
[`enrichment-2026-08-20-virustotal.json`](enrichment-2026-08-20-virustotal.json), because
it is a *degraded* run and should not stand in for the clean one above.

**Item 5's pacer is confirmed, by arithmetic that could not have come out this way by
accident.** The run made 7 VirusTotal attempts, so 6 inter-request gaps at the configured
15 seconds, on top of a 3.65s baseline measured without VirusTotal:

```
predicted 6 x 15.0 + 3.65 = 93.7s
observed                    93.90s
```

That is the pacer spacing real requests, not a fake clock in a unit test.

**VirusTotal's quota was exhausted**, so six of the seven attempts returned HTTP 429
`QuotaExceededError`. This is not the pacer being too aggressive: a single request issued
by hand after 20 seconds of idle returned the same 429, so no spacing would have helped.
One domain lookup did get through and returned real `last_analysis_stats`, which confirms
the domain endpoint.

**Item 7's base64 URL identifier is not confirmed live.** Both URL attempts hit 429
before VirusTotal ever evaluated the identifier, and a 429 says nothing about whether the
unpadded URL-safe encoding is the right one.

Mocking cannot close this, because the mock would be built from the same belief that
produced the code. What it can do is stop the fixture being *ours*: the encoding is now
pinned to the worked example published in VirusTotal's v3 URL documentation, which
specifies "unpadded base64 encoding, as defined in RFC 4648 section 3.2". That turned out
to matter more than expected — the previous test would have passed under padded standard
base64, because `https://evil.test/beacon` is exactly 24 bytes (no padding) and its
base64 contains no `+` or `/`, so both alphabets give the same string. The documented
40-byte example needs two padding characters and does discriminate.

What remains unproven is narrower: that the live API accepts the documented form. That
needs a key with quota available.

### What the failure did demonstrate

The degraded run exercised two safety mechanisms under genuinely adverse conditions
rather than simulated ones:

- After 3 consecutive VirusTotal failures the remaining VirusTotal lookups were skipped,
  with the reason recorded on the observation: `Lookups against virustotal stopped after
  3 consecutive failures.` The run reported `stopped_early=yes`.
- The failures were contained to VirusTotal. DNS, RDAP, AbuseIPDB, and URLhaus all
  returned their answers in the same run, which is what the two-pass executor is for.
- Errors are not cached (only `found` and `not_found` are), so a bad quota minute is not
  frozen into later runs.

The URLhaus listing recorded here is a point-in-time observation from 2026-08-20. Entries
are removed as URLs go offline, so a later run of the same case may return `not_found`
for it; that is the provider's record changing, not a regression.
