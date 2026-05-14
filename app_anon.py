import streamlit as st
import pandas as pd
import io

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PII Guardian",
    page_icon="🛡️",
    layout="wide",
)

# ── Sidebar ─────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ PII Guardian")
    st.markdown("---")

    st.subheader("🔒 Security Note")
    st.info(
        "**Local Mode — Zero Data Egress**\n\n"
        "All processing happens entirely in your device's RAM. "
        "No data is sent to any server, API, or cloud service. "
        "When you close this tab, nothing is retained.",
        icon="🔐",
    )

    st.markdown("---")
    st.subheader("⚙️ Detection Settings")
    entities = st.multiselect(
        "PII types to detect",
        options=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "LOCATION", "DATE_TIME", "NRP"],
        default=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"],
    )
    confidence_threshold = st.slider("Confidence threshold", 0.0, 1.0, 0.5, 0.05)

    st.markdown("---")
    st.caption("Built with Microsoft Presidio · Runs 100% offline")

# ── Engine initialisation (cached so it only loads once) ────────────────────────
@st.cache_resource(show_spinner="Loading NLP models — one moment…")
def load_engines():
    analyzer = AnalyzerEngine()
    anonymizer = AnonymizerEngine()
    return analyzer, anonymizer

analyzer, anonymizer = load_engines()

# ── Helpers ─────────────────────────────────────────────────────────────────────
OPERATOR_MAP = {
    "PERSON":          OperatorConfig("replace", {"new_value": "[NAME]"}),
    "EMAIL_ADDRESS":   OperatorConfig("replace", {"new_value": "[EMAIL]"}),
    "PHONE_NUMBER":    OperatorConfig("replace", {"new_value": "[PHONE]"}),
    "CREDIT_CARD":     OperatorConfig("replace", {"new_value": "[CREDIT_CARD]"}),
    "LOCATION":        OperatorConfig("replace", {"new_value": "[LOCATION]"}),
    "DATE_TIME":       OperatorConfig("replace", {"new_value": "[DATE]"}),
    "NRP":             OperatorConfig("replace", {"new_value": "[ID]"}),
}


def scrub_text(text: str, selected_entities: list, threshold: float) -> tuple[str, int]:
    """Return (scrubbed_text, hit_count) for a single cell value."""
    if not isinstance(text, str) or not text.strip():
        return text, 0

    results = analyzer.analyze(
        text=text,
        entities=selected_entities,
        language="en",
        score_threshold=threshold,
    )
    if not results:
        return text, 0

    operators = {e: OPERATOR_MAP[e] for e in selected_entities if e in OPERATOR_MAP}
    anonymized = anonymizer.anonymize(text=text, analyzer_results=results, operators=operators)
    return anonymized.text, len(results)


def scrub_dataframe(df: pd.DataFrame, selected_entities: list, threshold: float):
    """Return (clean_df, hits_df) where hits_df records hit counts per cell."""
    clean_df = df.copy()
    hits_df = pd.DataFrame(0, index=df.index, columns=df.columns)

    total_cells = df.shape[0] * df.shape[1]
    bar = st.progress(0, text="Scanning…")

    for col_idx, col in enumerate(df.columns):
        for row_idx in df.index:
            clean_val, hits = scrub_text(str(df.at[row_idx, col]), selected_entities, threshold)
            clean_df.at[row_idx, col] = clean_val
            hits_df.at[row_idx, col] = hits

        pct = (col_idx + 1) / len(df.columns)
        bar.progress(pct, text=f"Scanning column **{col}**…")

    bar.empty()
    return clean_df, hits_df


def df_to_csv_bytes(df: pd.DataFrame) -> bytes:
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return buf.getvalue().encode()


# ── Main UI ──────────────────────────────────────────────────────────────────────
st.title("🛡️ PII Guardian")
st.markdown("Upload a CSV, detect PII across every cell, and download a redacted copy.")

uploaded = st.file_uploader("Drop your CSV here", type=["csv"])

if uploaded is None:
    st.info("Awaiting file upload. No data leaves your machine.", icon="📂")
    st.stop()

# ── Load & preview ───────────────────────────────────────────────────────────────
try:
    raw_df = pd.read_csv(uploaded, dtype=str)
except Exception as e:
    st.error(f"Could not parse CSV: {e}")
    st.stop()

st.success(f"Loaded **{raw_df.shape[0]} rows × {raw_df.shape[1]} columns**")

with st.expander("👀 Raw data preview", expanded=False):
    st.dataframe(raw_df.head(20), use_container_width=True)

# ── Scan ─────────────────────────────────────────────────────────────────────────
if not entities:
    st.warning("Select at least one PII type in the sidebar.")
    st.stop()

if st.button("🔍 Scan & Redact", type="primary", use_container_width=True):
    with st.spinner("Analysing…"):
        clean_df, hits_df = scrub_dataframe(raw_df, entities, confidence_threshold)

    total_hits = int(hits_df.values.sum())
    affected_cols = (hits_df > 0).any().sum()

    # ── Metrics ──────────────────────────────────────────────────────────────────
    c1, c2, c3 = st.columns(3)
    c1.metric("PII detections", total_hits)
    c2.metric("Columns affected", f"{affected_cols} / {len(raw_df.columns)}")
    c3.metric("Rows scanned", raw_df.shape[0])

    st.markdown("---")

    # ── Side-by-side review ───────────────────────────────────────────────────────
    st.subheader("📋 Before vs After")

    col_left, col_right = st.columns(2)
    with col_left:
        st.markdown("**🔴 Original (dirty)**")
        st.dataframe(raw_df, use_container_width=True, height=400)
    with col_right:
        st.markdown("**🟢 Redacted (clean)**")
        st.dataframe(clean_df, use_container_width=True, height=400)

    # ── Hit map ───────────────────────────────────────────────────────────────────
    if total_hits > 0:
        with st.expander("🗺️ PII heat-map (detections per cell)", expanded=False):
            st.dataframe(
                hits_df.style.background_gradient(cmap="Reds", axis=None),
                use_container_width=True,
            )

    # ── Download ──────────────────────────────────────────────────────────────────
    st.markdown("---")
    st.download_button(
        label="⬇️ Download redacted CSV",
        data=df_to_csv_bytes(clean_df),
        file_name=f"redacted_{uploaded.name}",
        mime="text/csv",
        type="primary",
        use_container_width=True,
    )

    if total_hits == 0:
        st.success("No PII detected above the confidence threshold. Your data looks clean! ✅")
