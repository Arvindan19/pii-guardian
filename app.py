import streamlit as st
import pandas as pd
import io

from faker import Faker
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

st.set_page_config(page_title="PII Guardian", page_icon="🛡️", layout="wide")

fake = Faker()

# ── Sidebar ────────────────────────────────────────────────────────────────────
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
    st.subheader("⚙️ Detection Settings (Tab 1 only)")
    entities = st.multiselect(
        "PII types to detect",
        options=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "LOCATION", "DATE_TIME", "NRP"],
        default=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"],
    )
    confidence_threshold = st.slider("Confidence threshold", 0.0, 1.0, 0.5, 0.05)
    st.markdown("---")
    st.caption("Built with Microsoft Presidio · Runs 100% offline")


# ── Engines ────────────────────────────────────────────────────────────────────
@st.cache_resource(show_spinner="Loading NLP models — one moment…")
def load_engines():
    return AnalyzerEngine(), AnonymizerEngine()

analyzer, anonymizer = load_engines()


# ── Column mode faker types ────────────────────────────────────────────────────
COLUMN_FAKER_OPTIONS = {
    "Full name":         fake.name,
    "First name":        fake.first_name,
    "Last name":         fake.last_name,
    "Email":             fake.email,
    "Phone number":      fake.phone_number,
    "Date of birth":     fake.date_of_birth,
    "Date":              fake.date,
    "Address":           fake.address,
    "City":              fake.city,
    "Country":           fake.country,
    "Postcode / ZIP":    fake.postcode,
    "Company":           fake.company,
    "Job title":         fake.job,
    "Username":          fake.user_name,
    "Credit card":       fake.credit_card_number,
    "SSN / NRP":         fake.ssn,
    "ID number":         lambda: str(fake.random_number(digits=8)),
    "Random number":     lambda: str(fake.random_number()),
    "Keep original":     None,
}


# ── Shared helpers ─────────────────────────────────────────────────────────────
FAKER_MAP = {
    "PERSON":        fake.name,
    "EMAIL_ADDRESS": fake.email,
    "PHONE_NUMBER":  fake.phone_number,
    "CREDIT_CARD":   fake.credit_card_number,
    "LOCATION":      fake.city,
    "DATE_TIME":     fake.date,
    "NRP":           fake.ssn,
}


def remove_overlaps(results):
    sorted_results = sorted(results, key=lambda x: (x.start, -(x.end - x.start)))
    kept = []
    for r in sorted_results:
        if not any(r.start >= k.start and r.end <= k.end for k in kept):
            kept.append(r)
    return kept


def scrub_text(text, selected_entities, threshold):
    if not isinstance(text, str) or not text.strip():
        return text, 0
    results = analyzer.analyze(
        text=text, entities=selected_entities, language="en", score_threshold=threshold,
    )
    if not results:
        return text, 0
    results = remove_overlaps(results)
    operators = {
        e: OperatorConfig("custom", {"lambda": lambda x, e=e: FAKER_MAP[e]()})
        for e in selected_entities if e in FAKER_MAP
    }
    anonymized = anonymizer.anonymize(text=text, analyzer_results=results, operators=operators)
    return anonymized.text, len(results)


def scrub_dataframe(df, selected_entities, threshold):
    clean_df = df.copy()
    hits_df  = pd.DataFrame(0, index=df.index, columns=df.columns)
    cell_log = {}
    bar = st.progress(0, text="Scanning…")
    for col_idx, col in enumerate(df.columns):
        for row_idx in df.index:
            original = str(df.at[row_idx, col])
            fake_val, hits = scrub_text(original, selected_entities, threshold)
            clean_df.at[row_idx, col] = fake_val
            hits_df.at[row_idx, col]  = hits
            if hits > 0:
                cell_log[fake_val] = original
        bar.progress((col_idx + 1) / len(df.columns), text=f"Scanning column **{col}**…")
    bar.empty()
    return clean_df, hits_df, cell_log


def cell_log_to_df(cell_log):
    return pd.DataFrame([
        {"fake_value": fv, "original_value": ov} for fv, ov in cell_log.items()
    ])


def clean_series(series):
    return series.str.strip().str.strip("'").str.strip('"')


def df_to_csv_bytes(df):
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return buf.getvalue().encode()


# ── Multi-format file reader ───────────────────────────────────────────────────
SUPPORTED_TYPES = ["csv", "xlsx", "xls", "tsv", "json"]

def read_file(uploaded_file):
    """Read any supported file type into a DataFrame. Returns (df, error_string)."""
    name = uploaded_file.name.lower()
    try:
        if name.endswith(".csv"):
            return pd.read_csv(uploaded_file, dtype=str), None
        elif name.endswith(".tsv"):
            return pd.read_csv(uploaded_file, sep="\t", dtype=str), None
        elif name.endswith(".xlsx") or name.endswith(".xls"):
            xl = pd.ExcelFile(uploaded_file)
            if len(xl.sheet_names) == 1:
                return xl.parse(xl.sheet_names[0], dtype=str), None
            # Multiple sheets — let user pick
            return xl, None
        elif name.endswith(".json"):
            return pd.read_json(uploaded_file, dtype=str), None
        else:
            return None, f"Unsupported file type: {name}"
    except Exception as e:
        return None, str(e)


def df_to_xlsx_bytes(df):
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        df.to_excel(writer, index=False)
    return buf.getvalue()


def download_buttons(clean_df, log_df, raw_df, base_name):
    """Render the three download buttons with both CSV and XLSX options."""
    is_xlsx = base_name.lower().endswith((".xlsx", ".xls"))

    st.markdown("---")
    st.subheader("⬇️ Downloads")
    st.caption(
        "Share the **Fake file** freely. "
        "Store the **Lookup Table** somewhere only you can access."
    )

    fmt_col, _ = st.columns([1, 3])
    with fmt_col:
        out_fmt = st.radio("Output format", ["CSV", "XLSX"], horizontal=True,
                           index=1 if is_xlsx else 0, key=f"fmt_{base_name}")

    dl1, dl2, dl3 = st.columns(3)
    if out_fmt == "CSV":
        with dl1:
            st.download_button("⬇️ Fake file", df_to_csv_bytes(clean_df),
                f"fake_{base_name}.csv", "text/csv", type="primary", use_container_width=True)
        with dl2:
            st.download_button("🔑 Lookup Table", df_to_csv_bytes(log_df),
                f"lookup_{base_name}.csv", "text/csv", use_container_width=True)
        with dl3:
            st.download_button("📄 Original file", df_to_csv_bytes(raw_df),
                f"original_{base_name}.csv", "text/csv", use_container_width=True)
    else:
        with dl1:
            st.download_button("⬇️ Fake file", df_to_xlsx_bytes(clean_df),
                f"fake_{base_name}.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                type="primary", use_container_width=True)
        with dl2:
            st.download_button("🔑 Lookup Table", df_to_csv_bytes(log_df),
                f"lookup_{base_name}.csv", "text/csv", use_container_width=True)
        with dl3:
            st.download_button("📄 Original file", df_to_xlsx_bytes(raw_df),
                f"original_{base_name}.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True)


def relink(fake_df, lookup_df):
    """Swap fake values back to originals using lookup table."""
    lookup_df.columns = lookup_df.columns.str.strip().str.lstrip("\ufeff")
    if not {"fake_value", "original_value"}.issubset(lookup_df.columns):
        return None, list(lookup_df.columns)
    reverse_map = dict(zip(
        clean_series(lookup_df["fake_value"]),
        clean_series(lookup_df["original_value"])
    ))
    restored_df = fake_df.copy()
    for col in restored_df.columns:
        restored_df[col] = clean_series(restored_df[col]).replace(reverse_map)
    diffs = (fake_df != restored_df).sum().sum()
    return restored_df, diffs


# ══════════════════════════════════════════════════════════════════════════════
tab1, tab2, tab3 = st.tabs([
    "🔍 Scan & Anonymise",
    "🎯 Column Mode",
    "🔄 Re-link to Original",
])


# ─────────────────────────────────────────────────────────────────────────────
#  TAB 1 — AI SCAN
# ─────────────────────────────────────────────────────────────────────────────
with tab1:
    st.title("🔍 Scan & Anonymise")
    st.markdown(
        "Presidio AI scans every cell and replaces detected PII with realistic fake data. "
        "Best for unstructured text where PII could be hiding anywhere."
    )

    uploaded = st.file_uploader(
        "Drop your file here — CSV, XLSX, XLS, TSV, JSON",
        type=SUPPORTED_TYPES, key="t1_upload"
    )

    if uploaded is None:
        st.info("Awaiting file upload. No data leaves your machine.", icon="📂")
    else:
        result, err = read_file(uploaded)
        if err:
            st.error(err); st.stop()

        # Handle multi-sheet Excel
        if isinstance(result, pd.ExcelFile):
            sheet = st.selectbox("Multiple sheets found — pick one:", result.sheet_names, key="t1_sheet")
            raw_df = result.parse(sheet, dtype=str)
        else:
            raw_df = result

        if raw_df is None:
            st.error("Could not read file."); st.stop()

        st.success(f"Loaded **{raw_df.shape[0]} rows × {raw_df.shape[1]} columns**")
        with st.expander("👀 Raw data preview", expanded=False):
            st.dataframe(raw_df.head(20), use_container_width=True)

        if not entities:
            st.warning("Select at least one PII type in the sidebar.")
        elif st.button("🔍 Scan & Anonymise", type="primary", use_container_width=True, key="t1_scan"):
            with st.spinner("Analysing…"):
                clean_df, hits_df, cell_log = scrub_dataframe(raw_df, entities, confidence_threshold)

            total_hits    = int(hits_df.values.sum())
            affected_cols = (hits_df > 0).any().sum()

            c1, c2, c3 = st.columns(3)
            c1.metric("PII detections",   total_hits)
            c2.metric("Columns affected", f"{affected_cols} / {len(raw_df.columns)}")
            c3.metric("Rows scanned",     raw_df.shape[0])

            st.markdown("---")
            st.subheader("📋 Before vs After")
            col_left, col_right = st.columns(2)
            with col_left:
                st.markdown("**🔴 Original**")
                st.dataframe(raw_df, use_container_width=True, height=400)
            with col_right:
                st.markdown("**🟢 Anonymised**")
                st.dataframe(clean_df, use_container_width=True, height=400)

            if total_hits > 0:
                with st.expander("🗺️ Detection counts per cell", expanded=False):
                    st.dataframe(hits_df, use_container_width=True)

            st.markdown("---")

            if cell_log:
                log_df = cell_log_to_df(cell_log)
                st.subheader("🔑 Lookup Table")
                st.caption("Keep this private — it's your key to restore original values.")
                st.dataframe(log_df, use_container_width=True)
                base = uploaded.name.rsplit(".", 1)[0]
                download_buttons(clean_df, log_df, raw_df, base)
            else:
                st.success("No PII detected above the confidence threshold. ✅")
                st.download_button("⬇️ Download CSV", df_to_csv_bytes(clean_df),
                    f"clean_{uploaded.name}", "text/csv", type="primary", use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
#  TAB 2 — COLUMN MODE
# ─────────────────────────────────────────────────────────────────────────────
with tab2:
    st.title("🎯 Column Mode")
    st.markdown(
        "You choose exactly which columns to anonymise and what fake data type "
        "to replace them with. **100% reliable** — no AI detection needed. "
        "Perfect for structured data like names, phones, emails in known columns."
    )

    t2_upload = st.file_uploader(
        "Drop your file here — CSV, XLSX, XLS, TSV, JSON",
        type=SUPPORTED_TYPES, key="t2_upload"
    )

    if t2_upload is None:
        st.info("Upload a file to get started.", icon="📂")
    else:
        t2_result, t2_err = read_file(t2_upload)
        if t2_err:
            st.error(t2_err); st.stop()

        if isinstance(t2_result, pd.ExcelFile):
            t2_sheet = st.selectbox("Multiple sheets found — pick one:", t2_result.sheet_names, key="t2_sheet")
            t2_raw = t2_result.parse(t2_sheet, dtype=str)
        else:
            t2_raw = t2_result

        st.success(f"Loaded **{t2_raw.shape[0]} rows × {t2_raw.shape[1]} columns**")
        with st.expander("👀 Raw data preview", expanded=False):
            st.dataframe(t2_raw.head(10), use_container_width=True)

        st.markdown("---")
        st.subheader("⚙️ Configure each column")
        st.caption("Choose what fake data type to use for each column. Select **Keep original** to leave a column untouched.")

        faker_option_names = list(COLUMN_FAKER_OPTIONS.keys())

        # Build default guess per column name
        def guess_faker(col_name):
            col = col_name.lower()
            if any(k in col for k in ["full_name", "fullname", "name"]):       return "Full name"
            if any(k in col for k in ["first", "fname", "forename"]):          return "First name"
            if any(k in col for k in ["last", "lname", "surname"]):            return "Last name"
            if any(k in col for k in ["email", "mail"]):                        return "Email"
            if any(k in col for k in ["phone", "mobile", "tel"]):              return "Phone number"
            if any(k in col for k in ["dob", "birth", "birthday"]):            return "Date of birth"
            if any(k in col for k in ["date"]):                                 return "Date"
            if any(k in col for k in ["address", "street"]):                   return "Address"
            if any(k in col for k in ["city", "town"]):                        return "City"
            if any(k in col for k in ["country"]):                             return "Country"
            if any(k in col for k in ["post", "zip", "postcode"]):             return "Postcode / ZIP"
            if any(k in col for k in ["company", "org", "organisation"]):      return "Company"
            if any(k in col for k in ["job", "title", "role", "position"]):    return "Job title"
            if any(k in col for k in ["user", "username"]):                    return "Username"
            if any(k in col for k in ["card", "credit"]):                      return "Credit card"
            if any(k in col for k in ["ssn", "nrp", "national"]):              return "SSN / NRP"
            if any(k in col for k in ["id", "ref", "number"]):                 return "ID number"
            return "Keep original"

        col_config = {}
        cols_per_row = 2
        col_list = list(t2_raw.columns)

        for i in range(0, len(col_list), cols_per_row):
            row_cols = st.columns(cols_per_row)
            for j, col in enumerate(col_list[i:i+cols_per_row]):
                with row_cols[j]:
                    default = guess_faker(col)
                    choice = st.selectbox(
                        f"**{col}**",
                        options=faker_option_names,
                        index=faker_option_names.index(default),
                        key=f"col_cfg_{col}",
                    )
                    col_config[col] = choice

        st.markdown("---")

        # Preview sample
        with st.expander("👀 Preview first 3 rows with your settings", expanded=False):
            preview = t2_raw.head(3).copy()
            for col, choice in col_config.items():
                fn = COLUMN_FAKER_OPTIONS.get(choice)
                if fn is not None:
                    preview[col] = [fn() for _ in range(len(preview))]
            st.dataframe(preview, use_container_width=True)

        if st.button("🎯 Anonymise by Column", type="primary", use_container_width=True):
            t2_clean = t2_raw.copy()
            t2_log   = {}  # fake_cell -> original_cell per affected cell

            bar2 = st.progress(0, text="Anonymising…")
            active_cols = [(c, COLUMN_FAKER_OPTIONS[v]) for c, v in col_config.items() if COLUMN_FAKER_OPTIONS[v] is not None]

            for idx, (col, fn) in enumerate(active_cols):
                for row_idx in t2_raw.index:
                    original = str(t2_raw.at[row_idx, col])
                    faked    = fn()
                    t2_clean.at[row_idx, col] = faked
                    t2_log[faked] = original

                bar2.progress((idx + 1) / len(active_cols), text=f"Anonymising column **{col}**…")

            bar2.empty()

            changed_cols = len(active_cols)
            st.success(f"✅ Anonymised **{changed_cols}** column(s) across **{len(t2_raw)}** rows.")

            st.markdown("---")
            st.subheader("📋 Before vs After")
            cl, cr = st.columns(2)
            with cl:
                st.markdown("**🔴 Original**")
                st.dataframe(t2_raw, use_container_width=True, height=400)
            with cr:
                st.markdown("**🟢 Anonymised**")
                st.dataframe(t2_clean, use_container_width=True, height=400)

            t2_log_df = pd.DataFrame([
                {"fake_value": fv, "original_value": ov} for fv, ov in t2_log.items()
            ])

            st.markdown("---")
            st.subheader("🔑 Lookup Table")
            st.caption("Keep this private — upload it in the Re-link tab to restore originals.")
            st.dataframe(t2_log_df, use_container_width=True)

            t2_base = t2_upload.name.rsplit(".", 1)[0]
            download_buttons(t2_clean, t2_log_df, t2_raw, t2_base)


# ─────────────────────────────────────────────────────────────────────────────
#  TAB 3 — RE-LINK
# ─────────────────────────────────────────────────────────────────────────────
with tab3:
    st.title("🔄 Re-link Fake Data to Original")
    st.markdown(
        "Works with lookup tables from **both** Tab 1 and Tab 2. "
        "Upload your analysed fake CSV and the lookup table to restore all original values."
    )
    st.info(
        "**How this works**\n\n"
        "The lookup table stores every fake cell value and what it replaced. "
        "This tab does a find-and-replace across the entire CSV. "
        "Any new columns or formulas your analysts added are kept untouched.",
        icon="ℹ️",
    )

    col_a, col_b = st.columns(2)
    with col_a:
        fake_upload   = st.file_uploader("1️⃣  Analysed fake file",  type=SUPPORTED_TYPES, key="t3_fake")
    with col_b:
        lookup_upload = st.file_uploader("2️⃣  Lookup table (CSV)", type=["csv"], key="t3_lookup")

    if fake_upload and lookup_upload:
        try:
            f_result, f_err = read_file(fake_upload)
            if f_err:
                st.error(f_err); st.stop()
            if isinstance(f_result, pd.ExcelFile):
                f_sheet = st.selectbox("Sheet to restore:", f_result.sheet_names, key="t3_sheet")
                fake_df = f_result.parse(f_sheet, dtype=str)
            else:
                fake_df = f_result
            lookup_df = pd.read_csv(lookup_upload, dtype=str)
        except Exception as e:
            st.error(f"Could not read files: {e}")
            st.stop()

        restored_df, result = relink(fake_df, lookup_df)

        if restored_df is None:
            st.error(
                f"Lookup table columns found: `{result}`. "
                "Expected `fake_value` and `original_value`. "
                "Make sure you're uploading the lookup table generated by this app."
            )
        elif result == 0:
            st.warning("⚠️ No values were matched. Showing debug info below.", icon="⚠️")
            st.markdown("**Values in your fake CSV (first 10):**")
            sample = []
            for col in fake_df.columns:
                for val in fake_df[col].dropna().unique()[:2]:
                    sample.append({"column": col, "value": repr(val)})
            st.dataframe(pd.DataFrame(sample[:10]), use_container_width=True)
            st.markdown("**fake_value entries in your lookup table (first 10):**")
            st.dataframe(lookup_df["fake_value"].dropna().head(10).apply(repr).to_frame(), use_container_width=True)
            st.caption("If values look identical but still don't match, paste a screenshot here.")
        else:
            st.success(f"✅ Restored **{result}** values back to their originals.")
            st.markdown("---")
            st.subheader("📋 Before vs After re-link")
            col_left, col_right = st.columns(2)
            with col_left:
                st.markdown("**🟡 Analysed fake CSV**")
                st.dataframe(fake_df, use_container_width=True, height=400)
            with col_right:
                st.markdown("**🟢 Restored original values**")
                st.dataframe(restored_df, use_container_width=True, height=400)
            st.markdown("---")
            t3_base = fake_upload.name.rsplit(".", 1)[0]
            t3_fmt = st.radio("Output format", ["CSV", "XLSX"], horizontal=True, key="t3_fmt")
            if t3_fmt == "CSV":
                st.download_button(
                    "⬇️ Download restored file", df_to_csv_bytes(restored_df),
                    f"restored_{t3_base}.csv", "text/csv",
                    type="primary", use_container_width=True,
                )
            else:
                st.download_button(
                    "⬇️ Download restored file", df_to_xlsx_bytes(restored_df),
                    f"restored_{t3_base}.xlsx",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    type="primary", use_container_width=True,
                )

    elif fake_upload and not lookup_upload:
        st.warning("Please also upload your lookup table.", icon="⚠️")
    elif lookup_upload and not fake_upload:
        st.warning("Please also upload the analysed fake CSV.", icon="⚠️")
