import streamlit as st
import pandas as pd
import io
from datetime import datetime
import base64
from fpdf import FPDF
import openai

from pii_filter import detect_pii, mask_text
import language_tool_python

st.set_page_config(page_title="LLM Privacy Gate", layout="wide")

# Initialize language tool (grammar + spell)
tool = language_tool_python.LanguageTool('en-US')

# UI: header
st.title("LLM Privacy Gate — Local PII Filter + LLM")
st.markdown("""
This single-screen app autocorrects lightly, detects and masks private info locally, and sends a **masked** query to an online LLM.
""")

# Left column: Input & settings
left, right = st.columns([1, 1])

with left:
    st.subheader("User query")
    user_query = st.text_area("Type or paste your query (visible only locally):", height=220)
    st.write("Options")
    mask_mode = st.radio("Mask behavior", options=["replace", "warn", "block"], index=0, help="replace: send masked text to LLM; warn: don't mask (but log); block: prevent sending if PII present")
    preserve_pii_for_corrections = st.checkbox("Preserve (skip) PII when autocorrecting/grammar-fixing", value=True)

    correct_btn = st.button("Run correction + detect PII")
    send_btn = st.button("Send to LLM (masked)")

    st.markdown("**LLM settings**")
    openai_key = st.text_input("OpenAI API Key (will be used only to call LLM with masked input)", type="password", placeholder="sk-...")
    model_name = st.text_input("Model (example: gpt-4o-mini or gpt-4o)", value="gpt-4o-mini")

# Right column: results
with right:
    st.subheader("Preview & Result")
    preview_area = st.empty()
    st.markdown("**Redaction logs**")
    logs_area = st.empty()
    st.markdown("**LLM Response**")
    llm_area = st.empty()

# helper functions for non-destructive corrections
def safe_apply_language_tool(text: str, pii_spans):
    """
    Apply language_tool_python corrections BUT skip corrections that overlap any pii spans.
    We'll apply replacements on non-overlapping ranges only.
    """
    matches = tool.check(text)
    # build list of corrections as (start,end,repl)
    corrections = []
    for m in matches:
        if not m.replacements:
            continue
        start, end = m.offset, m.offset + m.errorLength
        # skip if overlaps pii spans
        overlap = False
        for p in pii_spans:
            if not (end <= p['start'] or start >= p['end']):
                overlap = True
                break
        if overlap:
            continue
        # pick first suggested replacement
        corrections.append((start, end, m.replacements[0]))

    if not corrections:
        return text

    # apply corrections left->right (non-overlapping)
    corrections = sorted(corrections, key=lambda x: x[0])
    out = []
    last = 0
    for s, e, repl in corrections:
        out.append(text[last:s])
        out.append(repl)
        last = e
    out.append(text[last:])
    return "".join(out)

def render_colored_html(original_text: str, spans):
    """
    Build HTML rendering with colored spans for the preview.
    Colors: high -> #ff6b6b (red), med -> #ffb86b (orange), low -> #c3ff6b (green)
    """
    if not spans:
        # safe text
        return "<div style='white-space:pre-wrap'>{}</div>".format(st.components.v1.html.escape(original_text) if hasattr(st.components.v1, 'html') else original_text)
    # build by walking through text
    parts = []
    last = 0
    color_map = { "high": "#ff6b6b", "medium": "#ffb86b", "low": "#c3ff6b" }
    for s in spans:
        if s['start'] > last:
            parts.append(escape_html(original_text[last:s['start']]))
        color = color_map.get(s.get("sensitivity","medium"), "#ffb86b")
        label = s.get("type","PII")
        snippet = escape_html(original_text[s['start']:s['end']])
        parts.append(f"<span style='background:{color}; padding:2px; border-radius:3px;' title='{label} ({s.get('sensitivity')})'>{snippet}</span>")
        last = s['end']
    if last < len(original_text):
        parts.append(escape_html(original_text[last:]))
    html = "<div style='white-space:pre-wrap; font-family: monospace;'>" + "".join(parts) + "</div>"
    return html

def escape_html(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

# State
if "last_logs" not in st.session_state:
    st.session_state["last_logs"] = []
if "last_masked" not in st.session_state:
    st.session_state["last_masked"] = ""
if "last_masked_text_to_send" not in st.session_state:
    st.session_state["last_masked_text_to_send"] = ""
if "last_pii_spans" not in st.session_state:
    st.session_state["last_pii_spans"] = []

if correct_btn:
    if not user_query.strip():
        st.warning("Enter some text to correct and detect.")
    else:
        # initial PII detection
        pii_spans = detect_pii(user_query)
        st.session_state["last_pii_spans"] = pii_spans

        # apply grammar & spelling corrections but skip pii spans if chosen
        if preserve_pii_for_corrections:
            corrected = safe_apply_language_tool(user_query, pii_spans)
        else:
            corrected = safe_apply_language_tool(user_query, [])

        # re-detect PII on corrected text to adjust spans to new offsets (we will re-run detection)
        pii_spans_after = detect_pii(corrected)
        st.session_state["last_pii_spans"] = pii_spans_after

        # masking
        masked_text, logs = mask_text(corrected, pii_spans_after, mode=mask_mode)
        st.session_state["last_masked"] = masked_text
        st.session_state["last_logs"] = logs
        st.session_state["last_masked_text_to_send"] = masked_text if mask_mode == "replace" else corrected

        preview_html = render_colored_html(corrected, pii_spans_after)
        preview_area.markdown("**Corrected text with PII highlighted :**", unsafe_allow_html=False)
        preview_area.markdown(preview_html, unsafe_allow_html=True)
        if logs:
            logs_df = pd.DataFrame(logs)
            logs_area.dataframe(logs_df)
        else:
            logs_area.info("No PII detected.")

if send_btn:
    if not user_query.strip():
        st.warning("Enter text before sending.")
    else:
        # ensure we have a masked version (if not, run detect + mask now)
        if not st.session_state.get("last_masked"):
            # run pipeline quickly
            pii_spans = detect_pii(user_query)
            st.session_state["last_pii_spans"] = pii_spans
            corrected = safe_apply_language_tool(user_query, pii_spans if preserve_pii_for_corrections else [])
            pii_spans_after = detect_pii(corrected)
            masked_text, logs = mask_text(corrected, pii_spans_after, mode=mask_mode)
            st.session_state["last_masked"] = masked_text
            st.session_state["last_logs"] = logs
            st.session_state["last_masked_text_to_send"] = masked_text if mask_mode == "replace" else corrected

        # if mode block and PII present -> block
        if mask_mode == "block" and st.session_state["last_pii_spans"]:
            st.error("Sending blocked: PII detected and mode is BLOCK. Remove PII or switch mask mode.")
        else:
            text_to_send = st.session_state["last_masked_text_to_send"]
            if not openai_key:
                st.error("Provide OpenAI API key to send to LLM.")
            else:
                # call OpenAI (example). Ensure you set your key
                openai.api_key = openai_key
                try:
                    # simple completion call — adjust per your preferred API
                    resp = openai.ChatCompletion.create(
                        model=model_name,
                        messages=[{"role":"user","content": text_to_send}],
                        max_tokens=800,
                        temperature=0.2
                    )
                    reply = resp["choices"][0]["message"]["content"]
                    llm_area.code(reply)
                except Exception as e:
                    st.error(f"LLM call failed: {e}")

    # show logs and masked text
    if st.session_state.get("last_masked"):
        st.success("Masked text prepared and (if allowed) sent to LLM.")
        st.markdown("**Masked text (sent to LLM)**")
        st.code(st.session_state["last_masked"])
        if st.session_state["last_logs"]:
            logs_area.dataframe(pd.DataFrame(st.session_state["last_logs"]))
        else:
            logs_area.info("No PII detected.")

# Export logs buttons
if st.session_state.get("last_logs"):
    st.markdown("---")
    st.write("Export redaction log:")
    dl_col1, dl_col2 = st.columns(2)
    df_logs = pd.DataFrame(st.session_state["last_logs"])
    with dl_col1:
        csv = df_logs.to_csv(index=False).encode('utf-8')
        st.download_button("Download CSV", data=csv, file_name=f"redaction_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
    with dl_col2:
        # build simple PDF
        pdf_buf = io.BytesIO()
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 8, f"Redaction log - {datetime.now().isoformat()}", ln=True)
        pdf.ln(4)
        # add rows
        for idx, row in df_logs.iterrows():
            pdf.multi_cell(0, 6, txt=f"{idx+1}. type: {row.get('type')} sens: {row.get('sensitivity')} mask: {row.get('mask')} orig: {row.get('orig')}")
            pdf.ln(1)
        pdf.output(pdf_buf)
        pdf_buf.seek(0)
        st.download_button("Download PDF", data=pdf_buf, file_name=f"redaction_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf", mime="application/pdf")

# Legend
st.markdown("""
**Legend:**  
- High sensitivity (red) — direct PII: name, phone, email, credit card, SSN-like.  
- Medium (orange) — orgs, locations, long numeric IDs.  
- Low (green) — URLs and other low-risk tokens.
""")
