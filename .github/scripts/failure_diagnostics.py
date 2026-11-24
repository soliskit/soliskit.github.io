"""Export typed failure facts, never raw logs or publishable release evidence."""

import json
import math
import os
import pathlib
import re
import shutil
import stat
import sys
import tempfile

STAGES = {
    "node-version",
    "bundled-npm-version",
    "bootstrap-locked-npm-once",
    "npm-version",
    "install-once",
    "build-once",
    "lint-once",
    "format-once",
    "product-types-once",
    "test-types-once",
    "source-units-once",
    "delivery-units-once",
    "python-style-once",
    "affected-traceability-once",
    "bind-before-browser",
    "hosted-browser-install-once",
    "source-browser-once",
    "delivery-browser-once",
    "source-browser-coverage-once",
    "validate-exact-rosters-once",
    "bind-after-browser",
}
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_METADATA = 4 * 1024 * 1024
MAX_FILES = 512
SECRET = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|"
    r"AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b|"
    r"(?i:authorization\s*[:=]|bearer\s+[A-Za-z0-9._~+/=-]{8,}|"
    r"(?:password|passwd|secret|token|api[_-]?key|cookie|session|auth)\s*[:=])"
)


def require(condition):
    if not condition:
        raise ValueError("diagnostic export refused")


def environment_secrets(environment):
    return [
        v
        for k, v in environment.items()
        if re.search(
            r"TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|COOKIE|SESSION|AUTH|PRIVATE_KEY",
            k,
            re.I,
        )
        and len(v) >= 8
    ]


def safe_read(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE)
        data = stream.read(MAX_FILE + 1)
        after = os.fstat(stream.fileno())
        require(len(data) <= MAX_FILE and len(data) == before.st_size)
        require(
            (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        )
        return data


def traversal_error(error):
    raise error


def nested_receipt(paths, name, selector):
    """Keep availability facts even when one receipt cannot supply typed facts."""
    if name not in paths:
        return {"present": False, "parsed": False, "status": "missing"}
    result = {"present": True, "parsed": False, "status": "malformed"}
    try:
        record = json.loads(safe_read(paths[name]))
    except (ValueError, UnicodeError, RecursionError):
        return result
    result.update(parsed=True, status="invalid")
    try:
        require(isinstance(record, dict))
        facts = selector(record)
    except ValueError:
        return result
    result.update(status="valid", facts=facts)
    return result


def bool_fields(record, names):
    selected = {}
    for field in names:
        if field in record:
            require(type(record[field]) is bool)
            selected[field] = record[field]
    return selected


def setup_facts(record):
    require(
        record.get("verdict")
        in ("INCOMPLETE", "PRIVILEGED_SETUP_NATIVE_COMPLETION_ONLY")
    )
    return {
        "verdict": record["verdict"],
        **bool_fields(record, ["interrupted"]),
        "errorPresent": bool(record.get("errors")),
        "retentionErrorPresent": bool(record.get("retentionErrors")),
    }


def native_facts(record):
    result = bool_fields(record, ["timeout", "interrupted"])
    if "rc" in record:
        rc = record["rc"]
        require(rc is None or (type(rc) is int and -255 <= rc <= 255))
        result["rc"] = rc
    result["errorPresent"] = bool(record.get("error") or record.get("errors"))
    result["receiptWriteErrorPresent"] = bool(record.get("receiptWriteError"))
    for field, names in [
        (
            "cleanup",
            [
                "groupAbsent",
                "leaderRetained",
                "term",
                "kill",
                "emergencyKill",
                "noChildStarted",
            ],
        ),
        ("descendants", ["allAbsent", "term", "kill", "noChildStarted"]),
    ]:
        if field in record:
            require(isinstance(record[field], dict))
            result[field] = bool_fields(record[field], names)
            result[field]["errorPresent"] = bool(
                record[field].get("error") or record[field].get("cleanupError")
            )
    return result


PHASE_MARKERS = {
    "packageSetupActivity": re.compile(
        r"(?im)^(?:Hit:|Get:|Ign:|Err:)\d+ |^Reading package lists|"
        r"^Building dependency tree|^Preparing to unpack |^Unpacking |^Setting up "
    ),
    "browserDownloadActivity": re.compile(
        r"(?im)^Downloading (?:Chromium|Chrome for Testing|WebKit|Firefox|FFMPEG)\b"
    ),
    "fetchErrorActivity": re.compile(
        r"(?im)^E: Failed to fetch |^W: Failed to fetch |"
        r"^Error: Download failed|^Error: Request to .* timed out"
    ),
}


def setup_phase_facts(paths, environment):
    """Fixed observations only. Never include output text or its digest."""
    streams = {}
    observed = dict.fromkeys(PHASE_MARKERS, False)
    complete = True
    for suffix in ["stdout", "stderr"]:
        name = "privileged-setup/fixed-browser-setup." + suffix
        if name not in paths:
            streams[suffix] = {"present": False, "status": "unknown"}
            complete = False
            continue
        data = safe_read(paths[name])
        fact = {"present": True, "bytes": len(data), "status": "unknown"}
        streams[suffix] = fact
        try:
            text = data.decode("utf8")
        except UnicodeError:
            complete = False
            continue
        if SECRET.search(text) or any(
            value in text for value in environment_secrets(environment)
        ):
            complete = False
            continue
        fact["status"] = "classified"
        for key, marker in PHASE_MARKERS.items():
            observed[key] = observed[key] or bool(marker.search(text))
    result = {
        key: True if value else False if complete else None
        for key, value in observed.items()
    }
    if result["packageSetupActivity"] and result["browserDownloadActivity"]:
        classification = "mixed-phase-markers-present"
    elif result["browserDownloadActivity"]:
        classification = "browser-download-markers-present"
    elif result["packageSetupActivity"]:
        classification = "package-setup-markers-present"
    else:
        classification = "unknown"
    return {**result, "classification": classification, "streams": streams}


SETUP_PHASES = ("dependency-preflight", "browser-download")
SETUP_STATUSES = {
    "installed",
    "missing-or-unconfigured",
    "unsupported",
    "parse-or-command-error",
    "timeout",
    "not-started",
    "failure",
    "downloaded",
}


PREFLIGHT_CHECKS = ("package-status", "package-audit", "playwright-dependency-dry-run")


def preflight_check_facts(record):
    """Parent phase identity must already have passed phase_facts binding."""
    checks = record.get("checks")
    if checks is None:
        return {"status": "unknown"}
    try:
        require(isinstance(checks, list) and 0 < len(checks) <= len(PREFLIGHT_CHECKS))
        require(all(isinstance(check, dict) for check in checks))
        require(
            [check.get("name") for check in checks]
            == list(PREFLIGHT_CHECKS[: len(checks)])
        )
        selected = []
        for check in checks:
            native = check.get("native")
            require(isinstance(native, dict))
            require(type(native.get("rc")) is int and -255 <= native["rc"] <= 255)
            require(
                all(type(native.get(key)) is bool for key in ("timeout", "interrupted"))
            )
            for field, flag in (
                ("cleanup", "groupAbsent"),
                ("descendants", "allAbsent"),
            ):
                require(isinstance(native.get(field), dict))
                require(type(native[field].get(flag)) is bool)
            facts = native_facts(native)
            healthy = (
                native["rc"] == 0
                and not native["timeout"]
                and not native["interrupted"]
                and not facts["errorPresent"]
                and not facts["receiptWriteErrorPresent"]
                and facts["cleanup"].get("groupAbsent") is True
                and facts["descendants"].get("allAbsent") is True
                and not any(
                    value
                    for key, value in facts["cleanup"].items()
                    if key != "groupAbsent"
                )
                and not any(
                    value
                    for key, value in facts["descendants"].items()
                    if key != "allAbsent"
                )
            )
            selected.append(
                {
                    "check": check["name"],
                    "status": "native-success" if healthy else "native-not-success",
                    "native": facts,
                }
            )
        return {"status": "valid", "checks": selected}
    except (ValueError, KeyError, TypeError):
        return {"status": "unknown"}


def phase_facts(record, phase, state):
    require(record.get("schema") == 1 and type(record["schema"]) is int)
    require(record.get("phase") == phase)
    require(isinstance(record.get("status"), str))
    require(record["status"] in SETUP_STATUSES)
    allowed = (
        SETUP_STATUSES - {"downloaded"}
        if phase == "dependency-preflight"
        else {
            "downloaded",
            "parse-or-command-error",
            "timeout",
            "not-started",
            "failure",
        }
    )
    require(record["status"] in allowed)
    expected = {
        "QUALIFICATION_HEAD": state["head"],
        "GITHUB_SHA": state.get("hostHead"),
        "GITHUB_RUN_ID": state["run"],
        "GITHUB_RUN_ATTEMPT": state["attempt"],
    }
    require(isinstance(expected["GITHUB_SHA"], str))
    require(bool(re.fullmatch(r"[a-f0-9]{40}", expected["GITHUB_SHA"])))
    require(record.get("identity") == expected)
    result = {"phase": phase, "status": record["status"], "identityMatched": True}
    if "elapsedSeconds" in record:
        elapsed = record["elapsedSeconds"]
        require(type(elapsed) in (float, int))
        require(math.isfinite(elapsed) and 0 <= elapsed <= 390)
        result["elapsedSeconds"] = elapsed
    if record["status"] == "not-started":
        require(record.get("native") is None)
    else:
        require(isinstance(record.get("native"), dict))
        result["native"] = native_facts(record["native"])
    if phase == "dependency-preflight":
        result["checkOutcomes"] = preflight_check_facts(record)
    return result


def typed_setup_results(paths, state):
    prefix = "privileged-setup/"
    return {
        "schema": 1,
        "phaseOrder": list(SETUP_PHASES),
        "phases": {
            phase: nested_receipt(
                paths,
                prefix + phase + ".json",
                lambda record, selected=phase: phase_facts(record, selected, state),
            )
            for phase in SETUP_PHASES
        },
    }


def setup_results(paths):
    prefix = "privileged-setup/"
    return {
        "invalidated": prefix + "SETUP_INVALIDATED.json" in paths,
        "setup": nested_receipt(paths, prefix + "setup-final.json", setup_facts),
        "native": nested_receipt(
            paths, prefix + "fixed-browser-setup.json", native_facts
        ),
    }


def export(source, destination, environment):
    source = pathlib.Path(source)
    destination = pathlib.Path(destination)
    require(source.is_dir() and not source.is_symlink())
    require(not destination.exists() and not destination.is_symlink())
    paths = {}
    total = metadata = 0
    for root, dirs, files in os.walk(
        source, followlinks=False, onerror=traversal_error
    ):
        for name in dirs + files:
            item = pathlib.Path(root) / name
            mode = item.lstat().st_mode
            require(stat.S_ISDIR(mode) or stat.S_ISREG(mode))
            if stat.S_ISREG(mode):
                size = item.stat().st_size
                total += size
                if item.suffix == ".json":
                    metadata += size
                require(
                    size <= MAX_FILE and total <= MAX_TOTAL and metadata <= MAX_METADATA
                )
                paths[item.relative_to(source).as_posix()] = item
                require(len(paths) <= MAX_FILES)
    require("supervisor.json" in paths)
    state = json.loads(safe_read(paths["supervisor.json"]))
    require(isinstance(state, dict) and state.get("verdict") == "INCOMPLETE")
    require(bool(re.fullmatch(r"[a-f0-9]{40}", str(state.get("head", "")))))
    for field in ["run", "attempt"]:
        require(isinstance(state.get(field), str))
        require(bool(re.fullmatch(r"[1-9][0-9]{0,19}", state[field])))
    output = {
        "kind": "FAILURE_DIAGNOSTICS_NOT_RELEASE_EVIDENCE",
        "schema": 1,
        "head": state["head"],
        "run": state["run"],
        "attempt": state["attempt"],
        "verdict": "INCOMPLETE",
        "stages": [],
    }
    for name in sorted(STAGES):
        if name + ".json" not in paths:
            continue
        record = json.loads(safe_read(paths[name + ".json"]))
        require(isinstance(record, dict))
        rc = record.get("rc")
        require(rc is None or (type(rc) is int and -255 <= rc <= 255))
        item = {"stage": name, "rc": rc}
        for field in ["timeout", "interrupted"]:
            value = record.get(field, False)
            require(type(value) is bool)
            item[field] = value
        # Arbitrary error strings, environments, argv and output never leave
        # the runner. Only their presence becomes a fixed-schema fact.
        item["errorPresent"] = bool(
            record.get("error")
            or record.get("errors")
            or record.get("receiptWriteError")
        )
        item["streams"] = {}
        for suffix in ["stdout", "stderr"]:
            filename = name + "." + suffix
            if filename in paths:
                data = safe_read(paths[filename])
                # No digest of raw output: short secrets can be guessed from
                # hashes too. Byte count is sufficient to show stream presence.
                item["streams"][suffix] = {"bytes": len(data)}
        if name == "hosted-browser-install-once":
            item["setupResults"] = setup_results(paths)
            item["typedSetupResults"] = typed_setup_results(paths, state)
            item["setupPhaseFacts"] = setup_phase_facts(paths, environment)
        output["stages"].append(item)
    encoded = (json.dumps(output, indent=2) + "\n").encode()
    text = encoded.decode()
    require(not SECRET.search(text))
    require(not any(value in text for value in environment_secrets(environment)))
    temporary = pathlib.Path(
        tempfile.mkdtemp(prefix="failure-diagnostics-", dir=destination.parent)
    )
    try:
        (temporary / "summary.json").write_bytes(encoded)
        temporary.rename(destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main():
    try:
        export(os.environ["QUALIFICATION_EVIDENCE"], sys.argv[1], os.environ)
    except (ValueError, OSError, UnicodeError, KeyError, IndexError):
        print("Failure diagnostics were refused; no diagnostic artifact created.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
