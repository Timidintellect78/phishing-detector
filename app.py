# dashboard/app.py
import streamlit as st
st.set_page_config(page_title="📧 Phishing Detector", layout="wide")

# Now safe to import anything
import sys
import os
import tempfile
import plotly.graph_objects as go

# ✅ Fix sys.path early
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ✅ Delay all app imports until AFTER set_page_config
from app.parser import parse_email_from_file
from detector import analyze_email
from report import generate_markdown_report
from urlcheck import check_url_virustotal
# 👇 Replace with st.secrets["VT_API_KEY"] if using Streamlit secrets
VT_API_KEY = ""

st.markdown("""
    <h1 style='text-align: center; color: #FF4B4B;'>Phishing Email Detection Dashboard</h1>
    <p style='text-align: center;'>Upload a .eml file and instantly analyze risk level and key indicators.</p>
""", unsafe_allow_html=True)

uploaded_file = st.file_uploader("📤 Upload an .eml file", type=["eml"])

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    parsed = parse_email_from_file(tmp_path)

    # Simulated values for testing — remove in production
    parsed['reply_to'] = "fraud@fake.com"
    parsed['spf_passed'] = False
    parsed['dkim_passed'] = True

    result = analyze_email(parsed)
    vt_results = {}

    color_map = {
        "safe": "green",
        "suspicious": "orange",
        "phishing": "red"
    }

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("📨 Email Summary")
        with st.expander("Details", expanded=True):
            st.markdown(f"**From:** `{parsed['from']}`")
            st.markdown(f"**To:** `{parsed['to']}`")
            st.markdown(f"**Subject:** `{parsed['subject']}`")
            st.markdown("**Body Preview:**")
            st.text(parsed['body'][:500] + "...")

        st.subheader("🔗 Links Found")
        for link in parsed['links']:
            st.code(link)
            vt_result = check_url_virustotal(link, VT_API_KEY)
            vt_results[link] = vt_result

            if vt_result.get("error"):
                st.info(f"⚠️ VirusTotal error: {vt_result['error']}")
            else:
                harmless = vt_result.get("harmless", "N/A")
                suspicious = vt_result.get("suspicious", "N/A")
                malicious = vt_result.get("malicious", "N/A")

                st.markdown(
                    f"✅ Harmless: {harmless} | ⚠️ Suspicious: {suspicious} | ❌ Malicious: {malicious}"
                )

        st.subheader("📄 Export Report")
        if st.button("Generate Markdown Report"):
            path = generate_markdown_report(parsed, result, vt_results)
            with open(path, "rb") as f:
                st.download_button("Download Report", f, file_name="phishing_report.md")

    with col2:
        st.subheader("🧠 Phishing Risk")
        gauge = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=result['score'],
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Risk Score"},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': color_map[result['label']]},
                'steps': [
                    {'range': [0, 30], 'color': "#DFF2BF"},
                    {'range': [30, 70], 'color': "#FFF8C6"},
                    {'range': [70, 100], 'color': "#FFBABA"}
                ],
            }
        ))
        st.plotly_chart(gauge)

        st.markdown(
            f"**Risk Level:** <span style='color:{color_map[result['label']]}; font-size: 24px;'>{result['label'].upper()}</span>",
            unsafe_allow_html=True
        )

        st.markdown("**Flags Detected:**")
        for flag in result['flags']:
            st.warning(flag)

# ✅ Footer
st.markdown("""
<hr style='margin-top: 3rem; margin-bottom: 0.5rem;'>
<div style='text-align: center; color: grey; font-size: 0.9rem;'>
    Built by Austin Deering 💻 | Powered by Python & Streamlit
</div>
<div style='margin-top: 1rem; font-size: 0.8rem; text-align: center; color: darkred;'>
    ⚠️ Disclaimer: This tool is provided for educational and informational purposes only.
    It is not guaranteed to be accurate or comprehensive. Do not rely on this tool as your sole method
    of threat detection. Always verify results with professional security tools and procedures.
</div>
""", unsafe_allow_html=True)

