# VGI TLSFP notebooks

[01 · Fingerprint groups are not identities](01_fingerprint_groups_are_not_identities.ipynb) compares JA3 and base JA4 TLS-client grouping over synthetic handshake bytes, preserves parsing coverage, and uses VGI X.509 to correlate separate certificate fingerprints through explicit capture IDs.

## Run

Install [uv](https://docs.astral.sh/uv/). From the repository root:

```sh
uv sync --project notebooks --frozen
uv run --project notebooks --frozen python notebooks/execute.py
```

The complete `notebooks/` directory also runs independently of either worker checkout:

```sh
cd notebooks
uv sync --frozen
uv run --frozen python execute.py
```

Initial setup downloads Python dependencies, the VGI community extension and two pinned native releases. Analysis reads only committed synthetic inputs. No Rust or Go toolchain, local worker build, credentials, live endpoints or packet capture is needed. Native releases were executed on macOS Apple silicon; supported platform archives are listed on each worker's release page.

In VS Code select `notebooks/.venv/bin/python` and use `notebooks/` as the kernel working directory. Other Jupyter editors can register the environment:

```sh
uv run --project notebooks --frozen python -m ipykernel install --user --name vgi-tlsfp-notebooks --display-name 'Python (vgi-tlsfp notebooks)'
```

Restart and run all after changing the visible parameter. Both VGI connections and analytical SQL remain expanded; imports, presentation, plotting, assertions and cleanup source are folded. Saved output embeds both charts.

## Experiment

```sh
uv run --project notebooks --frozen python notebooks/execute.py \
  --parameters '{"USE_JA4":false}' \
  --output-dir notebooks/validation/ja3-groups
```

The default is `USE_JA4=True`. Switching to false changes the grouping key to JA3, while retaining the same parsed population, raw fields, both TLS fingerprints and certificate associations. Reset to true for the saved default.

The runner requires a separate destination for overrides, rejects unknown names and saves only successful full executions. Failed runs preserve previous saved outputs. Experiment copies include assets, fixtures, helpers, environment and documentation. Generated review charts, logs and experimental copies are ignored.

## Portable workers and fixture provenance

The visible literal locations are `github-auto://Query-farm/vgi-tlsfp@v0.4.0` and `github-auto://Query-farm/vgi-x509@v0.4.0`. VGI downloads, verifies and caches each platform archive. Haybarn is pinned to 2.0.0rc11 in the isolated notebook lock. Upgrades require an explicit tag change and rerunning both settings.

`build_fixtures.py` is a small standard-library encoder for eight deterministic `.bin` files. Its ClientHello field shape follows the worker's canonical test fixture. It authors a baseline, a TLS-record wrapper around the same message, reversed cipher order, changed GREASE values, and changed SNI text. Three diagnostic files contain an incomplete ClientHello body with a plausible header, a ServerHello, and non-handshake text. SQL adds a missing-input row and repetitions, yielding twelve capture records, eight of which parse as ClientHellos.

These records were never transmitted. Some extension bodies are intentionally minimal, so parser success does not establish a valid negotiation. The worker accepts a bare handshake or single TLS record; it is not a TCP/TLS stream reassembler. All functions used here perform local parsing and hashing.

Regenerate the eight byte fixtures:

```sh
uv run --project notebooks --frozen python notebooks/build_fixtures.py /tmp/vgi-tlsfp-fixtures
```

The two PEM files are unchanged synthetic self-signed fixtures from the [X.509 notebook](https://github.com/Query-farm/vgi-x509/tree/6f0e8893f5c461f112d2076450869c1bff776475/notebooks). Their generator is published there; no private key files are included. The handshake SNI strings use those fixture names, and the notebook visibly authors their capture-to-certificate associations. No handshake negotiation, hostname verification, trust-chain check or endpoint inspection is performed.

## Interpretation

JA3 preserves cipher/extension wire order after GREASE removal; base JA4 sorts those fields and uses the effective advertised TLS version. This example changes cipher order only and preserves signature-algorithm order. Base JA4 is not invariant to arbitrary field changes. The legacy version 771 and base JA4 `t13` prefix refer to different version fields; neither proves a negotiated TLS version.

The header guard accepts both ClientHello and ServerHello structural headers. The incomplete-body fixture also passes the guard but does not parse as a ClientHello. Missing input, an unrecognized header and a recognized header with no client parse remain distinct. ServerHello has its own JA3S output, not client fingerprints.

Base JA4 places all eight decoded client records in one group; JA3 splits them into groups of six and two because the reversed-cipher variant changes the ordered pre-hash string. Record framing, changed GREASE values and different SNI text leave both fingerprints unchanged in these fixtures. The raw decoded fields still retain their differences.

The group table counts capture records, byte representations, supplied server names and certificate fingerprints separately. One client fingerprint can appear with two names and two certificates. Certificate SHA-256 and TLS client fingerprints describe different objects: correlate them through a trusted observation key such as capture ID, never by direct hash equality. These synthetic associations illustrate that relationship without proving identity, client software, trust or maliciousness.

Validation covers default and detached JA3 executions, four chart renderings, twelve SQL invariants plus population reconciliation, three runner guards and byte-for-byte regeneration of all eight handshake files. Source validation passed 30 Rust tests including a doctest, 36 stdio / 38 HTTP / 36 Unix SQL assertions (one case each), Clippy, rustfmt, warning-clean rustdoc and a locked native build. Metadata scored 100/100 L2 with zero findings. X.509 parsing uses its separately verified release. The polished default completed in 1.6 seconds; a detached JA3 run, including a new notebook environment, completed its kernel execution in 18.4 seconds. Original source, tests and Cargo files remain unchanged.

Official Query.Farm Strata Sun and VGI artwork is copied unchanged from the approved assets, with linked Query.Farm branding at the top and bottom.
