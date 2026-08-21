# The envelope case, and the duplication the residue could not see — 2026-08-21

[`source-data-residue-2026-08-20.md`](source-data-residue-2026-08-20.md) measured
`--reduce-source-data` and found one case it did almost nothing for: `examples/unknown.json`
recovered **1.1%** where every other case recovered a quarter to two fifths. That
measurement blamed a `raw`/`parsed` pair "duplicated inside `source_data`, which a
top-level filter cannot see". This is the follow-up, and it corrects that diagnosis before
fixing it.

## What was actually wrong

`unknown.json` is an envelope: `{id, name, type, parsed, raw}`, where `parsed` is the
platform's own normalized view of the case and `raw.content` the original record. Nothing
but identity sits at the top level, so the generic adapter had nothing to lift.

| example | canonical fields filled |
|---|---|
| generic-case.json | 5 / 10 |
| other-soar-case.json | 4 / 10 |
| splunk-soar.json | 8 / 10 |
| **unknown.json** | **0 / 10** |

Every content field was empty — description, severity, status, both timestamps, tags,
alerts, artifacts, comments, timeline — while the case's entire substance sat inside
`source_data` as an undigested blob. The residue then recovered 1.1% for the mundane
reason that **nothing had been lifted**, so there was nothing to subtract.

The duplication is real but it was never the cause, and it is smaller than claimed. Of
12,263 characters, the two views share 18 keys after snake-casing and only 12 hold
byte-identical values — about 1,500 characters, 12% of the file. "Dominates the largest
payload here" was wrong. The two views also disagree in ways that matter: `parsed` carries
6 entities and `raw.content` 3, the three shared ones carry an `investigation_context` only
`raw` has, `raw.content` holds 27 keys `parsed` lacks, and the scalars differ in case
(`HIGH` / `high`). Neither is a subset of the other, so neither can simply be deleted.

## The change

Two parts, both narrow.

**Normalization unwraps an envelope.** When the top-level record supplies no content field
at all, the generic adapter scores nested mappings up to two levels deep by how many
content aliases each answers, and normalizes from the best one if it answers at least
three. Identity falls back to the outer record, because a wrapper usually keeps the id
while the inner view has only a title, and `source_data` is still the whole outer object —
enrichment walks it and `source_paths` resolve against it exactly as before.

The trigger is what makes this safe: a case that fills even one content field takes the
path it always did. The floor of three is the guard from the other side, so an artifact
body carrying a `description` and a `status` of its own is not mistaken for the case —
which would be worse than not normalizing at all, because the result would look complete.

**The residue applies its rule at the depth the adapter read from.** Only the one record
the adapter is known to have consumed, and key by key rather than by dropping the subtree:
an envelope holds fields no adapter lifts (`verdict`, `entityKind` here), and deleting them
with the subtree would be the evidence loss the residue work already ruled out for
`child_containers`.

Two smaller things the shape forced. `entities` joins the generic artifact aliases, which
SOAR already had. And a `{"key": ..., "value": ...}` tag is joined as text rather than
passed through `str()`, which would have put a Python repr in the payload. Both are inert
for every recorded case here: none has a top-level `entities` key and none tags with
anything but strings.

## Measured

| case | payload | reduced | cut before | cut after |
|---|---|---|---|---|
| generic-case.json | 927 | 547 | 41.0% | 41.0% |
| other-soar-case.json | 855 | 504 | 41.1% | 41.1% |
| splunk-soar.json | 6,995 | 5,302 | 24.2% | 24.2% |
| **unknown.json** | 18,978 | 12,266 | **1.1%** | **35.4%** |

Measured on the rendered payload (`build_analysis_payload`, compact JSON), so the absolute
figures are not comparable with the earlier table, which measured `source_data` alone. The
percentages are.

Every other example, and all five benchmark cases, are byte-identical: the
`--explain --dry-run` preview diffs clean for three of the four examples and differs only
for the envelope one. The reduction on that case now behaves like the rest of the corpus.

**Read the size numbers carefully — this is not a 35% saving.** The reduced payload went
from 12,507 to 12,266 characters, under 2% smaller. What left the residue came back as
canonical fields; the information is the same and it is now *structured*. The unreduced
payload grew from 12,648 to 18,978 for the same reason, which is the duplication every
normalized case already carries by design and the reason `--reduce-source-data` exists.

The real result is the first table, not the second: 0 of 10 canonical fields to 7 of 10,
with the 6 entities lifted as artifacts. The model previously had to find the description,
severity, status, timestamps and entities itself inside a 12KB blob under two competing key
spellings.

**Nothing was lost.** Comparing every distinct leaf value in the reduced payload before and
against after: two values disappear (`SOURCE` and `manual`) and one appears
(`SOURCE: manual`) — the tag pair, joined. Everything else survives.

## What remains

`raw.content` is still sent whole, and about 1,500 characters of it — the title and the
description — restate lifted fields byte-for-byte in the other spelling. That is the
duplication the original note was reaching for, and it is deliberately not addressed here.
Removing it needs cross-spelling key matching plus a merge policy for two entity lists that
disagree on both membership and fields, which is a different and much riskier problem than
the key-exact rule used above. The safe half is done; the rest is not worth guessing at
without a second export of this shape to check against.

Also unchanged: only the **generic** adapter unwraps. SOAR exports have never presented
this shape here, and `detect_format` would have to route an envelope to generic anyway.
