import streamlit as st
import pandas as pd
import os
import math

# ---------------- LOGIN SYSTEM ----------------

def login():
    st.title("🔐 Admin Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == "admin" and password == "NotForyoU!123":
            st.session_state["logged_in"] = True
            st.success("Login Successful ✅")
            st.rerun()
        else:
            st.error("Invalid Username or Password ❌")

if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if not st.session_state["logged_in"]:
    login()
    st.stop()

# ---------------- ENTROPY FUNCTION ----------------

def calculate_entropy(data):
    entropy = 0
    length = len(data)

    for x in range(256):
        p_x = data.count(x) / length
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)

    return entropy


# ---------------- FILE SIGNATURE CHECK ----------------

def is_valid_image(data, ext):
    if ext in [".jpg", ".jpeg"]:
        return data[:3] == [255, 216, 255]
    elif ext == ".png":
        return data[:4] == [137, 80, 78, 71]
    return True


# ---------------- HYBRID ANALYSIS ----------------

def analyze_file(filepath):

    with open(filepath, "rb") as f:
        raw_data = f.read()

    data = list(raw_data)
    entropy = calculate_entropy(data)

    ext = os.path.splitext(filepath)[1].lower()
    valid_header = is_valid_image(data, ext)

    # -------- HYBRID CLASSIFICATION --------

    if ext in [".jpg", ".jpeg", ".png"]:

        if not valid_header:
            file_type = "Partially Encrypted Image"

        else:
            if entropy > 7.8:
                file_type = "Compressed Image"
            elif entropy > 7.2:
                file_type = "Normal Image"
            else:
                file_type = "Suspicious Image"

    else:
        if entropy > 7.5:
            file_type = "Encrypted"
        elif entropy > 6:
            file_type = "Compressed"
        else:
            file_type = "Normal"

    return entropy, file_type


# ---------------- STREAMLIT CONFIG ----------------

st.set_page_config(
    page_title="Hybrid Detection System",
    layout="wide",
    page_icon="🔐"
)

# ---------------- SIDEBAR ----------------

st.sidebar.title("Hybrid Detection System")

if st.sidebar.button("Logout"):
    st.session_state["logged_in"] = False
    st.rerun()

page = st.sidebar.selectbox(
    "Navigation",
    ["Dashboard", "File Detection", "Analytics", "History", "About"]
)

# ---------------- DASHBOARD ----------------

if page == "Dashboard":

    st.title("Hybrid Encryption & Compression Detection System")

    history_file = "scan_history.csv"

    if os.path.exists(history_file):
        data = pd.read_csv(history_file)

        encrypted = len(data[data["Type"].str.contains("Encrypted")])
        compressed = len(data[data["Type"].str.contains("Compressed")])
        normal = len(data[data["Type"].str.contains("Normal")])

    else:
        encrypted = compressed = normal = 0

    col1, col2, col3 = st.columns(3)

    col1.metric("Encrypted Files", encrypted)
    col2.metric("Compressed Files", compressed)
    col3.metric("Normal Files", normal)

    chart_data = pd.DataFrame({
        "Type": ["Encrypted", "Compressed", "Normal"],
        "Count": [encrypted, compressed, normal]
    })

    st.bar_chart(chart_data.set_index("Type"))

# ---------------- FILE DETECTION ----------------

elif page == "File Detection":

    st.header("Upload File for Detection")

    uploaded_file = st.file_uploader("Upload a file")

    if uploaded_file:

        with open(uploaded_file.name, "wb") as f:
            f.write(uploaded_file.getbuffer())

        if st.button("Run Detection"):

            entropy, file_type = analyze_file(uploaded_file.name)

            col1, col2 = st.columns(2)

            col1.metric("Entropy Score", round(entropy, 4))
            col2.metric("Detected Type", file_type)

            history = pd.DataFrame({
                "File": [uploaded_file.name],
                "Entropy": [entropy],
                "Type": [file_type]
            })

            if os.path.exists("scan_history.csv"):
                history.to_csv("scan_history.csv", mode="a", header=False, index=False)
            else:
                history.to_csv("scan_history.csv", index=False)

# ---------------- ANALYTICS ----------------

elif page == "Analytics":

    st.header("System Analytics")

    if os.path.exists("scan_history.csv"):

        data = pd.read_csv("scan_history.csv")

        st.subheader("Entropy Trend")
        st.line_chart(data["Entropy"])

        st.subheader("File Type Distribution")
        st.bar_chart(data["Type"].value_counts())

    else:
        st.info("No data available")

# ---------------- HISTORY ----------------

elif page == "History":

    st.header("Detection History")

    if os.path.exists("scan_history.csv"):
        data = pd.read_csv("scan_history.csv")
        st.dataframe(data)
    else:
        st.info("No scans performed yet")

# ---------------- ABOUT ----------------

elif page == "About":

    st.header("About")

    st.write("""
    The Hybrid Detection System is a digital forensic tool designed to accurately identify normal, compressed, encrypted, and partially encrypted data using a combination of entropy analysis and file signature verification. This hybrid approach reduces false positives and improves detection reliability, especially for image files where entropy alone is insufficient. The system analyzes uploaded files, validates structural integrity, and classifies them using enhanced logic. It supports investigators, cybersecurity professionals, and researchers by providing accurate detection, visual insights, and stored analysis results for further investigation.
    """)
