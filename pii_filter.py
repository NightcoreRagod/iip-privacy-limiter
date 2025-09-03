import re
from typing import List, Dict, Tuple
import spacy
import phonenumbers

# load spaCy globally (lazy load)
try:
    nlp = spacy.load("en_core_web_sm")
except Exception as e:
    # user should install model; this will throw if not installed
    raise RuntimeError("spaCy English model not found. Run: python -m spacy download en_core_web_sm") from e

# Define regexes
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"\b(?:https?://|www\.)\S+\b", re.IGNORECASE)
CREDITCARD_RE = re.compile(r"\b(?:\d[ -]*?){13,16}\b")  # crude credit-card number match
SSN_LIKE_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")  # US SSN pattern
# Generic long number (e.g., Aadhaar or other national identifiers) — adjust for your needs:
LONG_NUM_RE = re.compile(r"\b\d{9,16}\b")

# Sensitivity mapping
SENS_HIGH = "high"
SENS_MED = "medium"
SENS_LOW = "low"

# heuristic sensitivity by type
TYPE_TO_SENS = {
    "PHONE": SENS_HIGH,
    "EMAIL": SENS_HIGH,
    "CREDIT_CARD": SENS_HIGH,
    "SSN": SENS_HIGH,
    "PERSON": SENS_HIGH,
    "GPE": SENS_MED,      # geo-political entities (cities, countries)
    "LOC": SENS_MED,
    "ADDRESS": SENS_MED,
    "ORG": SENS_MED,
    "URL": SENS_LOW,
    "LONG_NUMBER": SENS_MED,
}

def find_phone_spans(text: str) -> List[Dict]:
    spans = []
    for match in phonenumbers.PhoneNumberMatcher(text, None):
        start, end = match.start, match.end
        spans.append({
            "type": "PHONE",
            "start": start,
            "end": end,
            "text": text[start:end],
            "sensitivity": TYPE_TO_SENS.get("PHONE", SENS_HIGH)
        })
    return spans

def regex_spans(text: str) -> List[Dict]:
    spans = []
    for m in EMAIL_RE.finditer(text):
        spans.append({"type": "EMAIL", "start": m.start(), "end": m.end(), "text": m.group(), "sensitivity": TYPE_TO_SENS["EMAIL"]})
    for m in URL_RE.finditer(text):
        spans.append({"type": "URL", "start": m.start(), "end": m.end(), "text": m.group(), "sensitivity": TYPE_TO_SENS["URL"]})
    for m in CREDITCARD_RE.finditer(text):
        spans.append({"type": "CREDIT_CARD", "start": m.start(), "end": m.end(), "text": m.group(), "sensitivity": TYPE_TO_SENS["CREDIT_CARD"]})
    for m in SSN_LIKE_RE.finditer(text):
        spans.append({"type": "SSN", "start": m.start(), "end": m.end(), "text": m.group(), "sensitivity": TYPE_TO_SENS["SSN"]})
    for m in LONG_NUM_RE.finditer(text):
        spans.append({"type": "LONG_NUMBER", "start": m.start(), "end": m.end(), "text": m.group(), "sensitivity": TYPE_TO_SENS["LONG_NUMBER"]})
    return spans

def spacy_ner_spans(text: str) -> List[Dict]:
    doc = nlp(text)
    spans = []
    for ent in doc.ents:
        etype = ent.label_
        # Map spaCy entity to our simpler types
        if etype in ("PERSON",):
            typ = "PERSON"
        elif etype in ("GPE",):
            typ = "GPE"
        elif etype in ("LOC",):
            typ = "LOC"
        elif etype in ("ORG",):
            typ = "ORG"
        else:
            typ = None

        if typ:
            spans.append({"type": typ, "start": ent.start_char, "end": ent.end_char, "text": ent.text, "sensitivity": TYPE_TO_SENS.get(typ, SENS_LOW)})
    return spans

def merge_spans(spans: List[Dict]) -> List[Dict]:
    """Merge overlapping spans and prefer higher sensitivity and longer span text."""
    if not spans:
        return []
    # sort by start then -end
    spans_sorted = sorted(spans, key=lambda s: (s["start"], -s["end"]))
    merged = []
    cur = spans_sorted[0].copy()
    for s in spans_sorted[1:]:
        if s["start"] <= cur["end"]:  # overlap
            # expand cur's end if needed
            if s["end"] > cur["end"]:
                cur["end"] = s["end"]
                cur["text"] = cur.get("text", "") + " " + s.get("text", "")
            # choose highest sensitivity type if conflict (high > med > low)
            sens_order = {SENS_HIGH: 3, SENS_MED: 2, SENS_LOW: 1}
            if sens_order.get(s.get("sensitivity", SENS_LOW), 1) > sens_order.get(cur.get("sensitivity", SENS_LOW), 1):
                cur["sensitivity"] = s["sensitivity"]
                cur["type"] = s.get("type", cur.get("type"))
        else:
            merged.append(cur)
            cur = s.copy()
    merged.append(cur)
    return merged

def detect_pii(text: str) -> List[Dict]:
    """Return list of detected PII spans [{'type','start','end','text','sensitivity'}]."""
    spans = []
    spans.extend(regex_spans(text))
    spans.extend(find_phone_spans(text))
    spans.extend(spacy_ner_spans(text))
    spans = merge_spans(spans)
    # normalize text field by slicing original text to make sure content matches
    for s in spans:
        s["text"] = text[s["start"]:s["end"]]
    return spans

def mask_text(text: str, spans: List[Dict], mode: str = "replace") -> Tuple[str, List[Dict]]:
    """
    mode: 'replace' -> replace each span with <TYPE_REDACTED_n>
          'warn'    -> keep text but annotate (no masking)
          'block'   -> returns text unchanged and will be used to block sending
    returns masked_text, log (list of {orig, mask, type, start, end})
    """
    if mode == "block":
        # return as-is and log nothing (blocking handled by caller)
        return text, []

    if mode == "warn":
        # no masking, but provide logs
        logs = []
        for i, s in enumerate(spans, start=1):
            logs.append({"orig": s["text"], "mask": None, "type": s["type"], "sensitivity": s["sensitivity"], "start": s["start"], "end": s["end"]})
        return text, logs

    # replace mode
    out = []
    logs = []
    last = 0
    for i, s in enumerate(spans, start=1):
        start, end = s["start"], s["end"]
        if start < last:
            # overlapping span that was merged earlier; skip
            continue
        out.append(text[last:start])
        mask = f"<{s['type']}_REDACTED_{i}>"
        out.append(mask)
        logs.append({"orig": s["text"], "mask": mask, "type": s["type"], "sensitivity": s["sensitivity"], "start": start, "end": end})
        last = end
    out.append(text[last:])
    return "".join(out), logs
