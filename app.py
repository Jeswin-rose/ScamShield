
import streamlit as st
import sqlite3
import re
from urllib.parse import urlparse
from datetime import datetime
from collections import Counter

# --------------------------------
# 1. PAGE CONFIGURATION
# --------------------------------

st.set_page_config(
    page_title="ScamShield",
    page_icon="🛡️",
    layout="wide"
)

# --------------------------------
# 2. DATABASE CONNECTION
# --------------------------------

def create_database():

    con = sqlite3.connect("scamshield.db")

    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        risk_score INTEGER,
        risk_level TEXT,
        categories TEXT,
        detected_words TEXT,
        urls TEXT,
        scan_date TEXT
    )
    """)

    con.commit()
    con.close()


create_database()


# --------------------------------
# 3. SUSPICIOUS KEYWORDS
# --------------------------------

scam_categories = {

    "Banking Scam": [
        "bank details",
        "account blocked",
        "verify your account",
        "credit card",
        "debit card",
        "net banking",
        "bank account"
    ],

    "Lottery / Prize Scam": [
        "won",
        "lottery",
        "prize",
        "lucky winner",
        "claim your reward",
        "congratulations"
    ],

    "Fake Job Scam": [
        "work from home",
        "job offer",
        "earn money",
        "part time job",
        "registration fee",
        "daily income"
    ],

    "Payment Scam": [
        "transfer money",
        "send money",
        "payment required",
        "processing fee",
        "urgent payment"
    ],

    "Account Security Scam": [
        "otp",
        "password",
        "click here",
        "verify immediately",
        "account suspended",
        "update your kyc"
    ]
}


# --------------------------------
# 4. URL CHECKING RULES
# --------------------------------

shortened_domains = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly"
]


def check_urls(message):

    urls = re.findall(
        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
        message,
        re.IGNORECASE
    )

    suspicious_urls = []
    url_warnings = []

    for url in urls:

        cleaned_url = url.rstrip(".,!?;:)")

        if cleaned_url.lower().startswith("www."):
            cleaned_url = "http://" + cleaned_url

        parsed = urlparse(cleaned_url)

        domain = parsed.hostname or ""

        warnings = []

        if parsed.scheme == "http":
            warnings.append("Uses HTTP instead of HTTPS")

        if domain.lower() in shortened_domains:
            warnings.append("Uses a shortened URL")

        if "@" in cleaned_url:
            warnings.append("Contains an @ symbol")

        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
            warnings.append("Uses an IP address instead of a domain name")

        if "xn--" in domain.lower():
            warnings.append("Contains an internationalized domain")

        if warnings:
            suspicious_urls.append(cleaned_url)
            url_warnings.append({
                "url": cleaned_url,
                "warnings": warnings
            })

    return urls, suspicious_urls, url_warnings


# --------------------------------
# 5. MESSAGE DETECTION
# --------------------------------

def analyze_message(message):

    text = message.lower()

    detected_words = []
    detected_categories = []

    # Check each scam category

    for category, keywords in scam_categories.items():

        category_found = False

        for word in keywords:

            if word in text:

                detected_words.append(word)
                category_found = True

        if category_found:
            detected_categories.append(category)

    # Remove duplicate words

    detected_words = list(set(detected_words))

    # Check URLs

    urls, suspicious_urls, url_warnings = check_urls(message)

    # Calculate score

    keyword_score = min(len(detected_words) * 15, 60)

    url_score = min(
        sum(len(item["warnings"]) * 15 for item in url_warnings),
        45
    )

    risk_score = min(keyword_score + url_score, 100)

    # Determine risk level

    if risk_score <= 20:
        risk_level = "Low"

    elif risk_score <= 60:
        risk_level = "Medium"

    else:
        risk_level = "High"

    return (
        detected_words,
        detected_categories,
        urls,
        suspicious_urls,
        url_warnings,
        risk_score,
        risk_level
    )


# --------------------------------
# 6. SAVE SCAN TO DATABASE
# --------------------------------

def save_scan(message, score, level,
              categories, words, urls):

    con = sqlite3.connect("scamshield.db")

    cur = con.cursor()

    cur.execute("""
    INSERT INTO scan_history
    (message, risk_score, risk_level,
     categories, detected_words, urls, scan_date)

    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        message,
        score,
        level,
        ", ".join(categories),
        ", ".join(words),
        ", ".join(urls),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    con.commit()
    con.close()


# --------------------------------
# 7. GET SCAN HISTORY
# --------------------------------

def get_history():

    con = sqlite3.connect("scamshield.db")

    cur = con.cursor()

    cur.execute("""
    SELECT * FROM scan_history
    ORDER BY id DESC
    """)

    records = cur.fetchall()

    con.close()

    return records


# --------------------------------
# 8. SAFETY RECOMMENDATIONS
# --------------------------------

def get_safety_tips(categories, url_warnings):

    tips = []

    if "Banking Scam" in categories:
        tips.append(
            "Never share your banking details through unknown messages."
        )

    if "Lottery / Prize Scam" in categories:
        tips.append(
            "Be careful with unexpected lottery or prize claims."
        )

    if "Fake Job Scam" in categories:
        tips.append(
            "Verify job offers through the company's official website."
        )

    if "Payment Scam" in categories:
        tips.append(
            "Verify payment requests before transferring money."
        )

    if "Account Security Scam" in categories:
        tips.append(
            "Never share your OTP or password with anyone."
        )

    if url_warnings:
        tips.append(
            "Avoid opening suspicious links. Check the website independently."
        )

    if not tips:
        tips.append(
            "No specific warning category was detected. "
            "Always verify unexpected messages."
        )

    tips.append(
        "Contact the organization using its official contact details "
        "if you are unsure about a message."
    )

    return tips


# --------------------------------
# 9. SIDEBAR NAVIGATION
# --------------------------------

st.sidebar.title("🛡️ ScamShield")

st.sidebar.write("Scam Message Detection System")

page = st.sidebar.radio(
    "Navigation",
    [
        "Home",
        "Dashboard",
        "Scan History",
        "About"
    ]
)


# --------------------------------
# 10. HOME PAGE
# --------------------------------

if page == "Home":

    st.title("🛡️ ScamShield")

    st.subheader("Smart Scam Message Detection System")

    st.write(
        "Check messages for potentially suspicious signs "
        "using predefined detection rules."
    )

    st.divider()

    message = st.text_area(
        "Enter your message here:",
        placeholder="Paste your message here...",
        height=180
    )

    if st.button("🔍 Check Message", type="primary"):

        if message.strip() == "":

            st.warning("Please enter a message first.")

        else:

            results = analyze_message(message)

            (
                detected_words,
                detected_categories,
                urls,
                suspicious_urls,
                url_warnings,
                risk_score,
                risk_level
            ) = results

            save_scan(
                message,
                risk_score,
                risk_level,
                detected_categories,
                detected_words,
                urls
            )

            st.divider()

            st.subheader("Analysis Result")

            # Risk score

            st.metric(
                "Risk Indicator",
                str(risk_score) + "/100"
            )

            if risk_level == "Low":
                st.success("🟢 Risk Level: Low")

            elif risk_level == "Medium":
                st.warning("🟠 Risk Level: Medium")

            else:
                st.error("🔴 Risk Level: High")

            st.progress(risk_score / 100)

            # Detected words

            st.subheader("Suspicious Words Detected")

            if detected_words:

                for word in detected_words:
                    st.write("•", word)

            else:

                st.write("No suspicious keywords detected.")

            # Categories

            st.subheader("Possible Scam Categories")

            if detected_categories:

                for category in detected_categories:
                    st.write("•", category)

            else:

                st.write("No matching scam categories detected.")

            # URL results

            st.subheader("URL Analysis")

            if urls:

                for url in urls:
                    st.write("Detected URL:", url)

                if url_warnings:

                    for item in url_warnings:

                        st.warning(item["url"])

                        for warning in item["warnings"]:
                            st.write("•", warning)

                else:

                    st.info(
                        "No URL warning signs were detected "
                        "by the current rules."
                    )

            else:

                st.write("No URLs detected in this message.")

            # Safety tips

            st.subheader("🛡️ Safety Recommendations")

            tips = get_safety_tips(
                detected_categories,
                url_warnings
            )

            for tip in tips:
                st.write("✔", tip)

            st.info(
                "This application uses rule-based detection. "
                "Its score is not a real fraud probability. "
                "A low score does not guarantee that a message is safe."
            )


# --------------------------------
# 11. DASHBOARD
# --------------------------------

elif page == "Dashboard":

    st.title("📊 ScamShield Dashboard")

    records = get_history()

    if records:

        total_scans = len(records)

        high_count = sum(
            1 for record in records if record[3] == "High"
        )

        medium_count = sum(
            1 for record in records if record[3] == "Medium"
        )

        low_count = sum(
            1 for record in records if record[3] == "Low"
        )

        col1, col2 = st.columns(2)

        col1.metric("Total Scans", total_scans)
        col2.metric("High Risk Messages", high_count)

        col3, col4 = st.columns(2)

        col3.metric("Medium Risk Messages", medium_count)
        col4.metric("Low Risk Messages", low_count)

        st.divider()

        st.subheader("Risk Level Statistics")

        st.bar_chart({
            "Messages": {
                "High": high_count,
                "Medium": medium_count,
                "Low": low_count
            }
        })

        st.subheader("Recent Scans")

        for record in records[:5]:

            st.write(
                record[7],
                "|",
                record[3],
                "|",
                str(record[2]) + "/100"
            )

    else:

        st.info(
            "No scan records available. "
            "Scan some messages to view dashboard statistics."
        )


# --------------------------------
# 12. SCAN HISTORY
# --------------------------------

elif page == "Scan History":

    st.title("📁 Scan History")

    records = get_history()

    if records:

        for record in records:

            with st.expander(
                "Scan #" + str(record[0]) +
                " - " + record[3] +
                " - " + str(record[2]) + "/100"
            ):

                st.write("Date:", record[7])

                st.write("Message:", record[1])

                st.write("Risk Level:", record[3])

                st.write("Risk Score:", record[2], "/100")

                st.write("Categories:", record[4] or "None")

                st.write("Detected Words:", record[5] or "None")

                st.write("URLs:", record[6] or "None")

        st.divider()

        if st.button("🗑️ Clear All History"):

            con = sqlite3.connect("scamshield.db")

            cur = con.cursor()

            cur.execute("DELETE FROM scan_history")

            con.commit()
            con.close()

            st.success("Scan history cleared.")

            st.rerun()

    else:

        st.info("No previous scans found.")


# --------------------------------
# 13. ABOUT PAGE
# --------------------------------

elif page == "About":

    st.title("About ScamShield")

    st.write(
        """
        ScamShield is a Python-based rule-driven
        scam message detection application.

        It identifies predefined suspicious words,
        possible scam categories and selected URL warning signs.

        Technologies Used:

        • Python
        • Streamlit
        • SQLite
        • Regular Expressions

        Project Type:

        Rule-Based Detection System

        This project does not use Artificial Intelligence
        or Machine Learning.
        """
    )

    st.warning(
        "ScamShield is an educational awareness tool. "
        "It cannot confirm whether a message or website is fraudulent."
    )


# --------------------------------
# 14. FOOTER
# --------------------------------

st.sidebar.divider()

st.sidebar.caption(
    "ScamShield | Rule-Based Detection System"
)
