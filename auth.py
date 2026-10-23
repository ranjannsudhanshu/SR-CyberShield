
import os
import re
import hmac
import hashlib
import secrets
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st


DB_PATH = Path(__file__).resolve().parent / "auth.db"
PBKDF2_ITERATIONS = 310_000
MAX_ADDITIONAL_ADMINS = 10


# ---------- DATABASE ----------
def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_db():
    """Create or migrate authentication tables without deleting existing data."""
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        }
   
        if "name" not in columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN name TEXT"
            )

        if "role" not in columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'"
            )

        if "status" not in columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'"
            )

        if "last_login" not in columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN last_login TIMESTAMP"
            )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success INTEGER NOT NULL,
                role TEXT NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


# ---------- SECURITY HELPERS ----------
def valid_email(email):
    email = (email or "").strip()
    return bool(
        re.fullmatch(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            email,
        )
    )


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PBKDF2_ITERATIONS,
    ).hex()


def hash_admin_password(password):
    salt = secrets.token_bytes(16).hex()
    password_hash = hash_password(password, salt)
    return f"{salt}${password_hash}"


def verify_admin_password(password, stored_hash):
    try:
        salt, saved_hash = stored_hash.split("$", 1)
        actual_hash = hash_password(password, salt)
        return hmac.compare_digest(actual_hash, saved_hash)
    except (ValueError, TypeError):
        return False


def admin_credentials():
    """Read the Main Admin credentials from environment variables."""
    email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    password = os.environ.get("ADMIN_PASSWORD", "")

    if not email or not password or not valid_email(email):
        return None

    return email, password


def record_attempt(email, success, role):
    """Record login activity without recording passwords."""
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO login_attempts (email, success, role)
            VALUES (?, ?, ?)
            """,
            (
                (email or "").strip().lower()[:254],
                int(bool(success)),
                role,
            ),
        )


# ---------- ADDITIONAL ADMIN CREATION ----------
def create_admin(name, email, password):
    """Allow only the Main Admin to create up to five additional admins."""

    main_admin = admin_credentials()

    current_email = (
        st.session_state.get("user_email", "").strip().lower()
    )
    current_role = st.session_state.get("user_role")

    if (
        not main_admin
        or current_email != main_admin[0]
        or current_role != "admin"
    ):
        return False, "Only the Main Admin can create additional admins."

    name = (name or "").strip()
    email = (email or "").strip().lower()

    if not name:
        return False, "Please enter the admin name."

    if not valid_email(email):
        return False, "Please enter a valid email address."

    if email == main_admin[0]:
        return False, "This email belongs to the Main Admin."

    if len(password) < 8:
        return False, "Password must contain at least 8 characters."

    if len(password) > 1024:
        return False, "Password is too long."

    try:
        with get_connection() as conn:
            # Avoid conflicts with existing Admin or User accounts.
            existing_admin = conn.execute(
                "SELECT 1 FROM admins WHERE email = ? COLLATE NOCASE",
                (email,),
            ).fetchone()

            if existing_admin:
                return False, "An Admin with this email already exists."

            existing_user = conn.execute(
                "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE",
                (email,),
            ).fetchone()

            if existing_user:
                return False, "A User account with this email already exists."

            # Count only additional admins, not the Main Admin.
            admin_count = conn.execute(
                "SELECT COUNT(*) FROM admins WHERE role = 'admin'"
            ).fetchone()[0]

            if admin_count >= MAX_ADDITIONAL_ADMINS:
                return False, "Maximum 5 additional Admins are allowed."

            conn.execute(
                """
                INSERT INTO admins (name, email, password_hash, role)
                VALUES (?, ?, ?, 'admin')
                """,
                (
                    name,
                    email,
                    hash_admin_password(password),
                ),
            )

        return True, "Additional Admin created successfully."

    except sqlite3.IntegrityError:
        return False, "An account with this email already exists."


# ---------- USER REGISTRATION ----------
def create_user(name, email, password):
    name = (name or "").strip()
    email = (email or "").strip().lower()

    if not name:
        return False, "Please enter your full name."

    if len(name) > 100:
        return False, "Name must be 100 characters or less."

    if not valid_email(email):
        return False, "Please enter a valid email address."

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    salt = secrets.token_hex(16)
    password_hash = hash_password(password, salt)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            existing_user = conn.execute(
                "SELECT id FROM users WHERE email = ? COLLATE NOCASE",
                (email,)
            ).fetchone()

            existing_admin = conn.execute(
                "SELECT id FROM admins WHERE email = ? COLLATE NOCASE",
                (email,)
            ).fetchone()

            if existing_user or existing_admin:
                return False, "This email is already registered."

            conn.execute(
                """
                INSERT INTO users
                (name, email, salt, password_hash, role, status)
                VALUES (?, ?, ?, ?, 'user', 'active')
                """,
                (name, email, salt, password_hash)
            )

        return True, "Account created successfully."

    except sqlite3.Error:
        return False, "Database error. Please try again."

# ---------- LOGIN ----------
def authenticate(email, password):
    email = (email or "").strip().lower()
    admin = admin_credentials()

    # Main Admin authentication uses environment variables.
    if admin and email == admin[0]:
        success = hmac.compare_digest(
            password.encode("utf-8"),
            admin[1].encode("utf-8"),
        )

        record_attempt(email, success, "admin")

        if success:
            return {
                "id": None,
                "email": email,
                "role": "admin",
            }

        return None

    # Additional Admin authentication.
    with get_connection() as conn:
        admin_user = conn.execute(
            """
            SELECT id, name, email, password_hash, role
            FROM admins
            WHERE email = ? COLLATE NOCASE
              AND role = 'admin'
            """,
            (email,),
        ).fetchone()

    if admin_user:
        success = verify_admin_password(
            password,
            admin_user["password_hash"],
        )

        record_attempt(email, success, "admin")

        if success:
            return {
                "id": admin_user["id"],
                "email": admin_user["email"],
                "role": "admin",
            }

        return None

    # Existing regular User authentication.
    with get_connection() as conn:
        user = conn.execute(
            """
            SELECT id, email, salt, password_hash, role, status
            FROM users
            WHERE email = ? COLLATE NOCASE
            """,
            (email,),
        ).fetchone()

        if user is None:
            record_attempt(email, False, "user")
            return None

        password_hash = hash_password(password, user["salt"])

        password_ok = hmac.compare_digest(
            password_hash,
            user["password_hash"],
        )

        success = password_ok and user["status"] == "active"

        record_attempt(email, success, user["role"])

        if not success:
            return None

        conn.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (user["id"],),
        )

        return {
            "id": user["id"],
            "email": user["email"],
            "role": user["role"],
        }


# ---------- LOGIN SESSION ----------
def _set_login_session(account):
    st.session_state["authenticated"] = True
    st.session_state["user_id"] = account["id"]
    st.session_state["user_email"] = account["email"]
    st.session_state["user_role"] = account["role"]
    st.rerun()


# ---------- LOGIN PAGE ----------
def render_auth_page():
    if st.session_state.get("authenticated", False):
        return True

    st.title("🛡️ CyberShield — URL Risk Detector")
    st.caption("Smart URL Security | Secure Login & Registration")

    admin_tab, user_tab, signup_tab = st.tabs(
        [
            "🔐 Admin Login",
            "👤 User Login",
            "📝 Create Account",
        ]
    )

    with admin_tab:
        with st.form("admin_login_form"):
            email = st.text_input(
                "Admin Email",
                key="admin_login_email",
            )
            password = st.text_input(
                "Admin Password",
                type="password",
                key="admin_login_password",
            )
            submitted = st.form_submit_button(
                "Login as Admin",
                use_container_width=True,
            )

        if submitted:
            if not email.strip() or not password:
                st.error("Enter your admin email and password.")
            else:
                try:
                    account = authenticate(email, password)
                except sqlite3.Error:
                    st.error(
                        "Authentication database error. Please try again."
                    )
                    account = None

                if account and account["role"] == "admin":
                    _set_login_session(account)
                else:
                    st.error("Invalid admin credentials.")

    with user_tab:
        with st.form("user_login_form"):
            email = st.text_input(
                "User Email",
                key="user_login_email",
            )
            password = st.text_input(
                "User Password",
                type="password",
                key="user_login_password",
            )
            submitted = st.form_submit_button(
                "Login as User",
                use_container_width=True,
            )

        if submitted:
            if not email.strip() or not password:
                st.error("Enter your user email and password.")
            else:
                try:
                    account = authenticate(email, password)
                except sqlite3.Error:
                    st.error(
                        "Authentication database error. Please try again."
                    )
                    account = None

                if account and account["role"] == "user":
                    _set_login_session(account)
                else:
                    st.error(
                        "Invalid user credentials, or account disabled."
                    )

    with signup_tab:
        with st.form("signup_form"):
            new_name = st.text_input("Full Name", key="signup_name")
            new_email = st.text_input(
                "Email Address",
                key="signup_email",
            )
            new_password = st.text_input(
                "Create Password",
                type="password",
                key="signup_password",
            )
            confirm_password = st.text_input(
                "Confirm Password",
                type="password",
                key="signup_confirm",
            )
            submitted = st.form_submit_button(
                "Create Account",
                use_container_width=True,
            )

        if submitted:
            if new_password != confirm_password:
                st.error("Passwords do not match.")
            else:
                try:
                    success, message = create_user(
    new_name,
    
    new_email,
    new_password,
)

                    if success:
                        st.success(message)
                    else:
                        st.error(message)

                except sqlite3.Error:
                    st.error(
                        "Could not create account. Please try again."
                    )
            st.divider()

    st.markdown(
        """
        <div style="
            text-align: center;
            padding: 15px;
            color: gray;
            font-size: 14px;
        ">
            Made with ❤️ by <b>SR CyberLabs</b>
        </div>
        """,
        unsafe_allow_html=True,
    )

    return False

    return False


# ---------- SIDEBAR / LOGOUT ----------
def render_logout_button():
    st.sidebar.write(
        f"Account: {st.session_state.get('user_email', '')}"
    )
    st.sidebar.caption(
        f"Role: {st.session_state.get('user_role', 'user').title()}"
    )

    if st.sidebar.button(
        "Logout",
        use_container_width=True,
    ):
        for key in (
            "authenticated",
            "user_id",
            "user_email",
            "user_role",
        ):
            st.session_state.pop(key, None)

        st.rerun()


# ---------- ADMIN PANEL ----------
def render_admin_panel():
    if st.session_state.get("user_role") != "admin":
        st.error("Administrator access required.")
        st.stop()

    st.title("🛡️ Administrator Panel")
    st.caption("Manage registered accounts and review login activity.")

    main_admin = admin_credentials()
    current_email = (
        st.session_state.get("user_email", "").strip().lower()
    )

    # Only the Main Admin sees the Admin creation form.
    if main_admin and current_email == main_admin[0]:
        st.subheader("Create Additional Admin")

        with st.form("create_additional_admin_form"):
            admin_name = st.text_input(
                "Admin Name",
                key="new_admin_name",
            )
            admin_email = st.text_input(
                "Admin Email",
                key="new_admin_email",
            )
            admin_password = st.text_input(
                "Admin Password",
                type="password",
                key="new_admin_password",
            )

            create_button = st.form_submit_button(
                "Create Admin",
                use_container_width=True,
            )

        if create_button:
            success, message = create_admin(
                admin_name,
                admin_email,
                admin_password,
            )

            if success:
                st.success(message)
            else:
                st.error(message)

        with get_connection() as conn:
            additional_admins = pd.read_sql_query(
                """
                SELECT name, email, created_at
                FROM admins
                WHERE role = 'admin'
                ORDER BY created_at DESC
                """,
                conn,
            )

        st.caption(
            f"Additional Admins: {len(additional_admins)} "
            f"/ {MAX_ADDITIONAL_ADMINS}"
        )
        st.dataframe(
            additional_admins,
            use_container_width=True,
            hide_index=True,
        )

    # Existing registered-user and login-activity features.
    with get_connection() as conn:
        users = pd.read_sql_query(
            """
            SELECT id, email, role, status, created_at, last_login
            FROM users
            ORDER BY created_at DESC
            """,
            conn,
        )

        activity = pd.read_sql_query(
            """
            SELECT email, attempted_at,
                   CASE WHEN success = 1 THEN 'Success'
                        ELSE 'Failed' END AS result,
                   role
            FROM login_attempts
            ORDER BY attempted_at DESC
            LIMIT 1000
            """,
            conn,
        )

        total_users = conn.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

        active_users = conn.execute(
            "SELECT COUNT(*) FROM users WHERE status = 'active'"
        ).fetchone()[0]

        successful_logins = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE success = 1"
        ).fetchone()[0]

        failed_logins = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE success = 0"
        ).fetchone()[0]

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Registered Users", total_users)
    col2.metric("Active Users", active_users)
    col3.metric("Successful Logins", successful_logins)
    col4.metric("Failed Attempts", failed_logins)

    st.subheader("Registered Users")
    st.dataframe(
        users,
        use_container_width=True,
        hide_index=True,
    )

    if not users.empty:
        st.download_button(
            "Export Users CSV",
            data=users.to_csv(index=False).encode("utf-8"),
            file_name="registered_users.csv",
            mime="text/csv",
        )

    st.subheader("Enable / Disable User Account")

    if users.empty:
        st.info("No registered users yet.")
    else:
        choices = {
            f"{row.email} (ID {row.id})": int(row.id)
            for row in users.itertuples()
        }

        selected_label = st.selectbox(
            "Select a user",
            list(choices.keys()),
        )
        selected_id = choices[selected_label]

        selected_status = users.loc[
            users["id"] == selected_id,
            "status",
        ].iloc[0]

        new_status = st.selectbox(
            "Account status",
            ["active", "disabled"],
            index=0 if selected_status == "active" else 1,
        )

        if st.button("Save Account Status"):
            with get_connection() as conn:
                conn.execute(
                    "UPDATE users SET status = ? WHERE id = ?",
                    (new_status, selected_id),
                )

            st.success("Account status updated.")
            st.rerun()

    st.subheader("Recent Login Activity")
    st.caption("Latest 1,000 attempts. Passwords are never logged.")

    st.dataframe(
        activity,
        use_container_width=True,
        hide_index=True,
    )

    if not activity.empty:
        st.download_button(
            "Export Login Activity CSV",
            data=activity.to_csv(index=False).encode("utf-8"),
            file_name="login_activity.csv",
            mime="text/csv",
        )
