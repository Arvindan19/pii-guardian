import random
import string
import streamlit as st
import pandas as pd
import io
from datetime import date

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
    # ── Student identity ──────────────────────────────────────────────────────
    "Student ID":         lambda: "490" + str(fake.random_int(min=100000, max=999999)),
    "Full name":          fake.name,
    "Preferred name":     fake.first_name,
    "First name":         fake.first_name,
    "Last name":          fake.last_name,
    "Date of birth":      fake.date_of_birth,
    "Gender":             lambda: fake.random_element(["Male", "Female", "Non-binary", "Prefer not to say"]),
    "Student email":      lambda: f"{fake.first_name().lower()}.{fake.last_name().lower()}@student.edu.au",
    "Personal email":     fake.email,
    "Phone":              fake.phone_number,
    # ── Address ───────────────────────────────────────────────────────────────
    "Home address":       fake.address,
    "Street":             fake.street_address,
    "City":               fake.city,
    "State":              lambda: fake.random_element(["NSW", "VIC", "QLD", "WA", "SA", "TAS", "ACT", "NT"]),
    "Postcode":           fake.postcode,
    "Country":            fake.country,
    "Nationality":        lambda: fake.random_element(["Australian", "Chinese", "Indian", "British", "Vietnamese", "South Korean", "Nepalese", "Indonesian", "Bangladeshi", "Malaysian"]),
    "Visa type":          lambda: fake.random_element(["Student Visa (500)", "Permanent Resident", "Australian Citizen", "Working Holiday (417)", "Skilled (189)", "Graduate (485)"]),
    # ── Academic ──────────────────────────────────────────────────────────────
    "Unit code":          lambda: fake.lexify("????", letters="ABCDEFGHIJKLMNOPQRSTUVWXYZ") + fake.numerify("####"),
    "Unit name":          lambda: fake.random_element(["Introduction to Programming", "Data Structures and Algorithms", "Calculus I", "Microeconomics", "Business Ethics", "Organic Chemistry", "Financial Accounting", "Machine Learning", "Corporate Law", "Human Anatomy", "Statistics for Business", "Software Engineering"]),
    "Grade (HD/D/CR/P/F)": lambda: fake.random_element(["HD", "D", "CR", "P", "F"]),
    "Mark (0-100)":       lambda: str(fake.random_int(min=0, max=100)),
    "WAM":                lambda: str(round(fake.pyfloat(min_value=50.0, max_value=100.0, right_digits=2), 2)),
    "GPA":                lambda: str(round(fake.pyfloat(min_value=1.0, max_value=7.0, right_digits=2), 2)),
    "Enrolment status":   lambda: fake.random_element(["Enrolled", "Withdrawn", "Deferred", "Completed", "Suspended"]),
    "Study mode":         lambda: fake.random_element(["Full-time", "Part-time", "Online", "Mixed"]),
    "Campus":             lambda: fake.random_element(["City Campus", "Parramatta Campus", "Penrith Campus", "Online"]),
    "Faculty":            lambda: fake.random_element(["Faculty of Engineering", "Faculty of Business", "Faculty of Science", "Faculty of Arts", "Faculty of Health", "Faculty of Law"]),
    "Course code":        lambda: fake.lexify("???", letters="ABCDEFGHIJKLMNOPQRSTUVWXYZ") + fake.numerify("####"),
    "Course name":        lambda: fake.random_element(["Bachelor of Computer Science", "Bachelor of Business", "Bachelor of Engineering", "Bachelor of Nursing", "Master of Data Science", "Bachelor of Laws", "Bachelor of Arts", "Bachelor of Psychology"]),
    "Year of study":      lambda: str(fake.random_int(min=1, max=5)),
    "Teaching period":    lambda: fake.random_element(["Autumn 2024", "Spring 2024", "Summer A 2024", "Summer B 2024", "Autumn 2025", "Spring 2025"]),
    # ── Staff ─────────────────────────────────────────────────────────────────
    "Staff ID":           lambda: "E" + fake.numerify("######"),
    "Department":         lambda: fake.random_element(["School of Computing", "School of Business", "School of Engineering", "Department of Mathematics", "Department of Psychology", "School of Nursing"]),
    "Position":           lambda: fake.random_element(["Lecturer", "Senior Lecturer", "Associate Professor", "Professor", "Tutor", "Research Assistant", "Unit Coordinator"]),
    "Employment type":    lambda: fake.random_element(["Full-time", "Part-time", "Casual", "Contract"]),
    # ── Financial ─────────────────────────────────────────────────────────────
    "TFN":                lambda: fake.numerify("### ### ###"),
    "BSB":                lambda: fake.numerify("###-###"),
    "Bank account":       lambda: fake.numerify("########"),
    "HECS amount":        lambda: "$" + str(fake.random_int(min=1000, max=50000)),
    "Scholarship name":   lambda: fake.random_element(["Vice-Chancellor's Scholarship", "Merit Scholarship", "Equity Scholarship", "International Student Award", "Community Service Award", "None"]),
    "Working with Children Check number": lambda: "WWC" + fake.numerify("#######") + fake.lexify("?", letters="ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    # ── Meta ──────────────────────────────────────────────────────────────────
    "Custom pattern":     None,
    "Keep original":      None,
}


def apply_pattern(pattern: str) -> str:
    """Replace pattern tokens: # → digit, @ → uppercase letter, YYYY/MM/DD → date parts."""
    today = date.today()
    result = pattern.replace("YYYY", str(today.year))
    result = result.replace("MM", f"{today.month:02d}")
    result = result.replace("DD", f"{today.day:02d}")
    return "".join(
        str(random.randint(0, 9)) if ch == "#"
        else random.choice(string.ascii_uppercase) if ch == "@"
        else ch
        for ch in result
    )


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
            col = col_name.lower().replace(" ", "_").replace("-", "_")
            # Student identity
            if col in ("student_id", "sid", "student_number") or col.startswith("student_id"):
                return "Student ID"
            if any(k in col for k in ["student_email", "uni_email", "university_email"]):
                return "Student email"
            if any(k in col for k in ["personal_email"]):                       return "Personal email"
            if any(k in col for k in ["preferred_name", "preferred"]):          return "Preferred name"
            if any(k in col for k in ["full_name", "fullname"]):                return "Full name"
            if any(k in col for k in ["first", "fname", "forename", "given"]):  return "First name"
            if any(k in col for k in ["last", "lname", "surname", "family"]):   return "Last name"
            if "name" in col:                                                    return "Full name"
            if any(k in col for k in ["dob", "birth", "birthday"]):             return "Date of birth"
            if any(k in col for k in ["gender", "sex"]):                        return "Gender"
            if any(k in col for k in ["phone", "mobile", "tel"]):               return "Phone"
            # Address
            if "street" in col:                                                  return "Street"
            if any(k in col for k in ["city", "town", "suburb"]):               return "City"
            if "state" in col and "status" not in col and "enrolment" not in col:
                return "State"
            if any(k in col for k in ["postcode", "post_code", "zip"]):         return "Postcode"
            if "country" in col:                                                 return "Country"
            if "nationality" in col:                                             return "Nationality"
            if "visa" in col:                                                    return "Visa type"
            if "address" in col:                                                 return "Home address"
            # Academic
            if any(k in col for k in ["unit_code", "unitcode", "subject_code"]): return "Unit code"
            if any(k in col for k in ["unit_name", "unitname", "subject_name", "subject"]): return "Unit name"
            if col in ("wam",) or col.startswith("wam"):                         return "WAM"
            if col in ("gpa",) or col.startswith("gpa"):                         return "GPA"
            if "grade" in col:                                                   return "Grade (HD/D/CR/P/F)"
            if "mark" in col or col in ("score", "final_mark", "marks"):         return "Mark (0-100)"
            if any(k in col for k in ["enrolment", "enrollment"]):               return "Enrolment status"
            if any(k in col for k in ["study_mode", "studymode", "mode_of_study"]): return "Study mode"
            if "campus" in col:                                                  return "Campus"
            if "faculty" in col:                                                 return "Faculty"
            if any(k in col for k in ["course_code", "coursecode"]):            return "Course code"
            if any(k in col for k in ["course_name", "coursename"]):            return "Course name"
            if "course" in col:                                                  return "Course name"
            if any(k in col for k in ["year_of_study", "study_year", "year_level"]): return "Year of study"
            if any(k in col for k in ["teaching_period", "semester", "session", "term", "trimester"]): return "Teaching period"
            # Staff
            if any(k in col for k in ["staff_id", "staffid", "employee_id", "emp_id"]): return "Staff ID"
            if "department" in col or col == "dept":                             return "Department"
            if any(k in col for k in ["position", "job_title", "jobtitle"]):    return "Position"
            if any(k in col for k in ["employment_type", "employment", "contract_type"]): return "Employment type"
            # Financial
            if col == "tfn" or "tax_file" in col:                               return "TFN"
            if col == "bsb" or col.startswith("bsb"):                           return "BSB"
            if any(k in col for k in ["bank_account", "account_number", "account_no"]): return "Bank account"
            if any(k in col for k in ["hecs", "help_debt", "hecs_debt"]):       return "HECS amount"
            if "scholarship" in col:                                             return "Scholarship name"
            if any(k in col for k in ["wwc", "working_with_children"]):         return "Working with Children Check number"
            # Fallbacks
            if any(k in col for k in ["email", "mail"]):                        return "Personal email"
            if any(k in col for k in ["id", "ref"]):                            return "Student ID"
            return "Keep original"

        col_config = {}
        col_patterns = {}
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
                    if choice == "Custom pattern":
                        col_patterns[col] = st.text_input(
                            "Pattern  (# = digit · @ = letter · YYYY / MM / DD = date)",
                            key=f"col_pat_{col}",
                            placeholder="e.g. UNIT-#### or SEM-@@##",
                        )

        st.markdown("---")

        # Preview sample
        with st.expander("👀 Preview first 3 rows with your settings", expanded=False):
            preview = t2_raw.head(3).copy()
            for col, choice in col_config.items():
                if choice == "Custom pattern":
                    pat = col_patterns.get(col, "")
                    if pat:
                        preview[col] = [apply_pattern(pat) for _ in range(len(preview))]
                else:
                    fn = COLUMN_FAKER_OPTIONS.get(choice)
                    if fn is not None:
                        preview[col] = [fn() for _ in range(len(preview))]
            st.dataframe(preview, use_container_width=True)

        if st.button("🎯 Anonymise by Column", type="primary", use_container_width=True):
            t2_clean = t2_raw.copy()
            t2_log   = {}  # fake_cell -> original_cell per affected cell

            bar2 = st.progress(0, text="Anonymising…")
            active_cols = []
            for c, v in col_config.items():
                if v == "Custom pattern":
                    pat = col_patterns.get(c, "")
                    if pat:
                        active_cols.append((c, lambda p=pat: apply_pattern(p)))
                elif COLUMN_FAKER_OPTIONS[v] is not None:
                    active_cols.append((c, COLUMN_FAKER_OPTIONS[v]))

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
