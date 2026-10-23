import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="CyberShield AI",
    page_icon="🛡️",
    layout="wide"
)

from auth import (
    init_auth_db,
    render_auth_page,
    render_logout_button,
    render_admin_panel,
)
from url_analyzer import analyze_url


# Keep the page configuration before other Streamlit UI commands.
st.set_page_config(
    page_title="SR CyberShield",
    page_icon="🛡️",
    layout="wide",
)

# Use paths relative to this app file so the databases remain in the project folder.

# Use paths relative to this app file.
PROJECT_DIR = Path(__file__).resolve().parent
DB_FILE = PROJECT_DIR / "history.db"


def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                url TEXT NOT NULL,
                risk TEXT NOT NULL,
                score INTEGER NOT NULL
            )
            """
        )

        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(scans)"
            ).fetchall()
        }

        if "user_email" not in columns:
            conn.execute(
                "ALTER TABLE scans ADD COLUMN user_email TEXT"
            )


def save_scan(result, user_email):
    user_email = (user_email or "").strip().lower()

    if not user_email:
        raise ValueError("Logged-in user email is required.")

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            INSERT INTO scans
                (scanned_at, url, risk, score, user_email)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(
                    timespec="seconds"
                ),
                result["url"],
                result["risk"],
                result["score"],
                user_email,
            ),
        )


def get_history(user_email):
    user_email = (user_email or "").strip().lower()

    if not user_email:
        return pd.DataFrame(
            columns=["scanned_at", "url", "risk", "score"]
        )

    with sqlite3.connect(DB_FILE) as conn:
        return pd.read_sql_query(
            """
            SELECT scanned_at, url, risk, score
            FROM scans
            WHERE user_email = ?
            ORDER BY id DESC
            LIMIT 100
            """,
            conn,
            params=(user_email,),
        )



# Initialize the existing authentication and scan-history databases.
init_auth_db()
init_db()

# Show the login/register screen to visitors who are not signed in.
if not render_auth_page():
    st.stop()

render_logout_button()

# Admins see the admin panel, not the URL-scanner interface.
if st.session_state.get("user_role") == "admin":
    render_admin_panel()
    st.stop()

# Regular users continue to the URL scanner.
st.title("🛡️ CyberShield — URL Risk Detector")
st.caption("Smart URL Security Analysis | Explainable Risk Scoring")

st.info(
    "Privacy: This app analyzes URL text locally. It does not visit the "
    "submitted website or send the URL to an external service."
)

with st.form("url_form"):
    url_input = st.text_input(
        "Enter a URL",
        placeholder="https://example.com",
    )
    submitted = st.form_submit_button(
        "Analyze URL",
        type="primary",
    )


if submitted:
    result = analyze_url(url_input)

    if not result["valid"]:
        reasons = result.get("reasons") or ["Please enter a valid URL."]
        st.error("Invalid URL: " + str(reasons[0]))
    else:
        save_scan(
            result,
            st.session_state.get("user_email", "")
        )
        st.session_state["last_result"] = result


if "last_result" in st.session_state:
    result = st.session_state["last_result"]

    st.divider()
    st.subheader("Analysis Result")

    col1, col2, col3 = st.columns(3)
    col1.metric("Risk Score", f'{result["score"]}/100')
    col2.metric("Risk Level", result["risk"])
    col3.metric("Hostname", result["hostname"])

    if result["risk"] == "HIGH":
        st.error("High risk indicators detected. Avoid opening this URL unless verified.")
    elif result["risk"] == "MEDIUM":
        st.warning("Some risk indicators were detected. Verify the destination.")
    else:
        st.success("Few obvious indicators detected. This does not guarantee safety.")

    st.progress(max(0, min(100, int(result["score"]))) / 100)

    st.markdown("**URL analyzed**")
    st.code(result["url"])

    st.markdown("**Findings**")
    for reason in result.get("reasons", []):
        st.markdown(f"- {reason}")

    st.caption(
        "This is a heuristic prototype, not a verified phishing or malware scanner."
    )

st.divider()
st.subheader("Recent Scan History")
st.error("TEST: Updated CyberShield AI")


history = get_history(
    st.session_state.get("user_email", "")
)

if history.empty:
    st.write("No valid URL scans yet.")
else:
    st.dataframe(history, use_container_width=True, hide_index=True)

    csv_data = history.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download History as CSV",
        data=csv_data,
        file_name="url_scan_history.csv",
        mime="text/csv",
    )

st.divider()

st.markdown(
    """
    <div style="
        text-align: center;
        padding: 18px 10px;
        color: #888888;
        font-size: 14px;
    ">
        <div style="font-size: 16px; font-weight: 600;">
            🛡️ CyberShield — URL Risk Detector
        </div>
        <div style="margin-top: 6px;">
            Made with ❤️ by <strong>SR CyberLabs</strong>
        </div>
        <div style="margin-top: 5px; font-size: 12px;">
            Cybersecurity Project
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)