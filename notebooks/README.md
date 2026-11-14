# TLSFP examples

| Notebook | Question | Run |
|---|---|---|
| [01 · Fingerprint groups are not identities](01_fingerprint_groups_are_not_identities.ipynb) | Which authored handshake differences change JA3/base JA4 groups, and how do certificate associations differ from client fingerprints? | [Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-tlsfp/blob/main/notebooks/01_fingerprint_groups_are_not_identities.ipynb) |
| [02 · Reconstruct fingerprints from fields](02_reconstruct_fingerprints_from_fields.ipynb) | Can extracted fields reproduce byte-based JA3, JA4 and JA3S, and what happens when JA4 receives the legacy version? | [Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-tlsfp/blob/main/notebooks/02_reconstruct_fingerprints_from_fields.ipynb) |

Both use the native **TLSFP v0.4.0** release through visible `github-auto` ATTACH SQL.
Notebook 01 also uses **X.509 v0.4.0** for local certificate parsing. No compiler,
credentials, packet capture, endpoint inspection or live TLS negotiation is needed.

In Colab choose **Runtime → Run all**. Setup installs the base shared package and
retrieves verified companions. Compatible Colab kernel and plotting libraries stay
installed. If an older setup already replaced those libraries, save your work,
choose **Runtime → Disconnect and delete runtime**, reconnect and open the current
notebook. Local publication uses the separate `[runner]` extra:

```sh
uv sync --locked
uv run --locked vgi-notebooks
uv run --locked vgi-notebooks 01_fingerprint_groups_are_not_identities.ipynb --parameters '{"USE_JA4":false}' --output-dir artifacts/ja3
uv run --locked vgi-notebooks 02_reconstruct_fingerprints_from_fields.ipynb --parameters '{"JA4_USES_LEGACY_VERSION":true}' --output-dir artifacts/legacy-version
```

The [shared standard](https://github.com/Query-farm/vgi-example-notebooks/blob/v0.3.0/docs/standard.md),
runner, branding, SVG presentation and Colab compatibility live in
[vgi-example-notebooks v0.3.0](https://github.com/Query-farm/vgi-example-notebooks).
`tlsfp_example.py` contains only this example's charts and interpretations; analytical
calls stay in visible SQL. Saved SVG outputs have matching assets under `charts/`
for GitHub rendering. Keep those assets with the notebooks.

## Inputs and interpretation

`build_fixtures.py` deterministically encodes the eight authored handshake files.
The certificate PEM fixtures are synthetic self-signed certificates. These inputs
exercise parser and fingerprint behavior; their minimal extension bodies are not
claimed to describe a negotiable TLS session. The notebooks make no client identity,
certificate trust or malicious-traffic inference. Certificate associations are
explicit authored capture-ID links, not equality between fingerprint domains.

Notebook 02 supplies known builder fields that the worker's ClientHello decoder
does not expose, including signature algorithms, point formats and effective version.
A real field-only pipeline must preserve these inputs rather than guessing them.
Its experiment changes only the version supplied to JA4; JA3 and JA3S remain fixed.

The two narratives demonstrate all ten named public functions in the v0.4.0 runtime
catalog. `coverage.json` records the catalog, executed cells, review and current-source
comparison. README listings alone are not used as catalog evidence.

Defaults and both parameter experiments are executed and reviewed. Notebook-only
bootstrap and the Colab-compatible shared dependencies are checked separately from
a manually operated hosted Colab session. Worker source and published binaries are
unchanged by these examples.
