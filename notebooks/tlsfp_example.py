"""Presentation for the TLS fingerprint narratives; computation stays in SQL."""

import matplotlib.pyplot as plt
from IPython.display import display
from matplotlib.ticker import MaxNLocator
from vgi_notebooks import finish as finish_chart, prose

SOURCE = "Authored handshake records · TLSFP + X.509 v0.4.0 · Local parsing only"


def finish(fig, title, subtitle, name):
    finish_chart(fig, title, subtitle, SOURCE, name=name)


def plot_population(coverage):
    palette = {
        "ClientHello decoded": "#267358",
        "Header recognized; no ClientHello": "#c57b40",
        "Header not recognized": "#456fba",
        "Missing input": "#8b9790",
    }
    fig, ax = plt.subplots(figsize=(12, 7))
    bars = ax.barh(
        coverage.input_state,
        coverage.capture_records,
        color=[palette[s] for s in coverage.input_state],
        height=0.55,
    )
    ax.bar_label(bars, padding=6, fontsize=12)
    ax.invert_yaxis()
    ax.set_xlim(0, int(coverage.capture_records.max()) * 1.2)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.set_xlabel("Synthetic capture records · Full input population")
    ax.grid(axis="y", visible=False)
    finish(
        fig,
        "A header guard is not a client parse",
        "All input rows retained · Client and server roles remain distinct",
        "input-coverage",
    )
    prose(
        f"The audit retains **{int(coverage.capture_records.sum())} input records**. "
        "A plausible header and a ServerHello can both pass the guard without yielding a ClientHello. "
        "This population audit stays fixed when the grouping rule changes."
    )


def plot_groups(groups, scheme):
    fig, ax = plt.subplots(figsize=(12, 6.5))
    bars = ax.barh(groups.group_label, groups.capture_records, color="#267358", height=0.40)
    ax.bar_label(bars, padding=6, fontsize=12)
    ax.set_ylim(len(groups) - 0.5, -0.5)
    ax.set_xlim(0, int(groups.capture_records.max()) * 1.2)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.set_xlabel("Decoded ClientHello records · Counts are not identities")
    ax.grid(axis="y", visible=False)
    finish(
        fig,
        "The grouping rule changes the partition",
        f"{scheme} · Successfully parsed clients only · Full hashes in table",
        "fingerprint-groups",
    )
    prose(
        f"**{int(groups.capture_records.sum())} decoded client records** form **{len(groups)} {scheme} groups**. "
        "Inspect the server-name and certificate counts below: one client fingerprint can occur with multiple supplied names and different certificate bytes. "
        "Those associations come from the authored capture IDs, not equality between fingerprint domains."
    )
    display(groups)


def plot_agreement(comparison, legacy):
    colors = ["#226B58" if value else "#C27638" for value in comparison.matches]
    fig, ax = plt.subplots(figsize=(10.8, 4.7))
    for i, (row, color) in enumerate(zip(comparison.itertuples(), colors, strict=True)):
        ax.scatter(i, 0, s=1100, marker="s", color=color)
        ax.text(
            i, -0.20, "Matches" if row.matches else "Differs", ha="center", fontsize=12, color=color
        )
    ax.set_xticks(range(len(comparison)), comparison.fingerprint)
    ax.set_yticks([])
    ax.set_xlim(-0.5, len(comparison) - 0.5)
    ax.set_ylim(-0.40, 0.25)
    ax.grid(False)
    count = int(comparison.matches.sum())
    finish_chart(
        fig,
        f"{count} of {len(comparison)} field reconstructions match the bytes",
        "JA4 receives the legacy version"
        if legacy
        else "JA4 receives the effective supported version",
        "Synthetic builder fields · TLSFP v0.4.0 · Same underlying hello messages",
        name="field-reconciliation",
    )
    prose(
        f"**{count} of {len(comparison)} fingerprints agree.** "
        + (
            "Only JA4 changes when the legacy version is substituted: it describes an advertised TLS 1.2 capability instead of the fixture’s effective TLS 1.3 capability. JA3 still needs the legacy field, and JA3S still uses the supplied server fields."
            if legacy
            else "Both input routes agree when the fields preserve each algorithm’s contract. JA3 uses the legacy version; JA4 uses the effective supported version and needs additional signature-algorithm fields; JA3S uses the server-selected cipher and server extensions."
        )
    )
