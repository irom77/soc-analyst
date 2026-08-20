# Live enrichment verification (2026-08-20)

The first run of the enrichment stack against **real providers**. Items 5, 6, and 7 had
until now been verified only offline, against fakes — including, for item 7, a URLhaus
response shape that was my own fixture agreeing with itself. This run closes part of
that gap and is explicit about the part it does not.

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

Providers reached: Cloudflare DNS, the RDAP registries, and AbuseIPDB.
**VirusTotal and URLhaus were not contacted** — see "What this did not verify".

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
never run live.

## Item 7 — the keyless half only

Confirmed live: a URL field emits **two** observables, the URL and its host, and the host
observable's `source_paths` carries the `#host` suffix while the email's carries
`#domain`. The email address was recorded and sent to no provider. The private address
`10.42.0.7` drew no reputation lookup. `8.8.8.8` reached both RDAP and AbuseIPDB.

Not confirmed: **the URLhaus request shape and its `query_status` handling, and
VirusTotal's base64 URL identifier.** Both need keys that are not configured, so item 7's
genuinely uncertain part remains uncertain. The run did exercise the keyless fallback,
which correctly named `ABUSE_CH_AUTH_KEY` in its skip reason.

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
