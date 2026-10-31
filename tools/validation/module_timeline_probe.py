"""Observe the unchanged diagnostic expression; retain a redacted full timeline."""
import codecs
import hashlib
import ntpath
import re
from collections import Counter
from datetime import datetime

import host_discovery_trace as original

MAX_BYTES = 4 * 1024 * 1024


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_reference(value, pshome):
    value = value.strip(" \t'\"")
    normalized = ntpath.normcase(ntpath.normpath(value))
    root = ntpath.normcase(ntpath.join(str(pshome), "Modules")) + "\\"
    label = None
    if normalized.startswith(root):
        label = "pshome_modules/" + normalized[len(root):].replace("\\", "/")
    else:
        match = re.fullmatch(r"[a-z]:\\program files(?: \(x86\))?\\(windowspowershell|powershell)\\modules\\(.+)", normalized)
        if match:
            label = "programfiles_modules/" + match[1] + "/" + match[2].replace("\\", "/")
    if label and not re.fullmatch(r"[a-z0-9_. /-]{1,400}", label):
        label = None
    return {"file_key": digest(normalized), "system_relative_file": label}


def classify(message, pshome):
    message = message.strip()
    original_message = message
    # PS5.1 Modules emits the trace operation before its actual message.
    # CommandDiscovery does not consistently include this prefix.
    message = re.sub(r"^WriteLine\s+", "", message)
    known = original.event(message, pshome) or original.modules_event(message, pshome)
    row = dict(known) if known else {"type": "unclassified"}
    for prefix, kind in (("Started analysis: ", "analysis_start"),
                         ("Finished analysis: ", "analysis_end"),
                         ("Requested caching for ", "cache_request"),
                         ("Analyzing path: ", "analyzing_path"),
                         ("Attempting to load module: ", "module_load_attempt"),
                         ("Found in module: ", "command_found_in_module")):
        if message.startswith(prefix):
            row = {"type": kind, **file_reference(message[len(prefix):], pshome)}
            break
    # Unknown text is never exported. Classify its vocabulary and keep a hash.
    if message.startswith("Caching command: "):
        row = {"type": "caching_command"}
    row["message_sha256"] = digest(original_message)
    row["message_length"] = len(original_message)
    row["terms"] = sorted(set(re.findall(
        r"\b(?:analysis|analyzing|cache|cached|module|manifest|import|export|loading|loaded|script|exception|error)\b",
        message.lower())))
    return row


def summarize(raw, pshome):
    encoding = "utf-16" if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) else "utf-8-sig"
    text = raw.decode(encoding)
    events = []
    pending = None
    headers = Counter()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        timestamp = re.fullmatch(r"DateTime=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?Z)", line)
        if timestamp:
            datetime.fromisoformat(timestamp[1].replace("Z", "+00:00"))
            if pending is not None:
                pending["timestamp_utc"] = timestamp[1]
            pending = None
            continue
        match = re.fullmatch(r"(?:DEBUG:\s*)?(CommandDiscovery|Modules)\s+([A-Za-z]+):\s*\d+\s*:\s*(.*)", line)
        if match:
            pending = classify(match[3], pshome)
            pending.update(source=match[1], trace_kind=match[2], line=len(events) + 1, timestamp_utc=None)
            headers[match[1] + ":" + match[2]] += 1
        else:
            pending = {"type": "unparsed_line", "message_sha256": digest(line),
                       "message_length": len(line), "timestamp_utc": None}
        events.append(pending)
    timed = [row for row in events if row["timestamp_utc"]]
    gaps = []
    for left, right in zip(timed, timed[1:]):
        delta = (datetime.fromisoformat(right["timestamp_utc"].replace("Z", "+00:00")) -
                 datetime.fromisoformat(left["timestamp_utc"].replace("Z", "+00:00"))).total_seconds()
        if delta >= 0.05:
            gaps.append({"seconds": round(delta, 6), "before": left, "after": right})
    active = {}
    for row in events:
        if row["type"] == "analysis_start":
            active[row["file_key"]] = row
        elif row["type"] == "analysis_end":
            active.pop(row["file_key"], None)
    return {"state": "recognized" if headers else "unrecognized", "full_file_parsed": True,
            "raw_sha256": hashlib.sha256(raw).hexdigest(), "total_bytes": len(raw),
            "trace_headers": dict(headers), "counts": dict(Counter(e["type"] for e in events)),
            "events": events, "largest_gaps": sorted(gaps, key=lambda x: x["seconds"], reverse=True)[:12],
            "unfinished_analyses": list(active.values())}


def trace_summary(path, pshome):
    try:
        info = path.lstat()
        if not original.stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("not_regular")
        if info.st_size > MAX_BYTES:
            return {"state": "unknown", "reason": "trace_exceeds_bound", "total_bytes": info.st_size}
        with path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
            if original.os.fstat(stream.fileno()).st_size != info.st_size or len(raw) != info.st_size:
                raise ValueError("changed_trace")
        return summarize(raw, pshome)
    except (OSError, ValueError, UnicodeError) as error:
        return {"state": "unknown", "error_kind": type(error).__name__}


if __name__ == "__main__":
    original.trace_summary = trace_summary
    raise SystemExit(original.main())
