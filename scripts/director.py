import streamlit as st
import pandas as pd
import os
import math
import numpy as np
import matplotlib.pyplot as plt
import csv

# ---------------- LOGIN SYSTEM ----------------

def login():
    st.title("🔐 Admin Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == "admin" and password == "1234":
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

# ---------------- SAFE CSV READER ----------------

def safe_read_csv(file):
    try:
        return pd.read_csv(file, on_bad_lines='skip')
    except:
        return pd.DataFrame()

# ---------------- ENTROPY ----------------

def calculate_entropy(data):
    entropy = 0
    length = len(data)

    if length == 0:
        return 0

    for x in range(256):
        p_x = data.count(x) / length
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)

    return entropy

# ---------------- BLOCK ENTROPY ----------------

def block_entropy(data, block_size=1024):
    return [
        calculate_entropy(data[i:i+block_size])
        for i in range(0, len(data), block_size)
    ]

# ---------------- FILE SIGNATURE ----------------

def check_file_signature(data, filename):
    ext = os.path.splitext(filename)[1].lower()

    if ext in [".jpg", ".jpeg"]:
        return data[:3] == [255, 216, 255]
    elif ext == ".png":
        return data[:4] == [137, 80, 78, 71]
    else:
        return True

# ---------------- HYBRID ANALYSIS ----------------

def analyze_file(filepath):

    with open(filepath, "rb") as f:
        raw = f.read()

    data = list(raw)

    entropy = calculate_entropy(data)
    blocks = block_entropy(data)

    block_var = max(blocks) - min(blocks) if blocks else 0
    header_valid = check_file_signature(data, filepath)

    ext = os.path.splitext(filepath)[1].lower()

    # -------- IMAGE LOGIC --------
    if ext in [".jpg", ".jpeg", ".png"]:

        if not header_valid:
            file_type = "Partially Encrypted Image"

        elif block_var > 1.5:
            file_type = "Partially Encrypted Image"

        elif entropy > 7.9:
            file_type = "Encrypted Image"

        elif entropy > 7.5:
            file_type = "Compressed Image"

        else:
            file_type = "Normal Image"

    # -------- TEXT / OTHER --------
    else:

        if block_var > 2:
            file_type = "Partially Encrypted"

        elif entropy > 7.5:
            file_type = "Encrypted"

        elif entropy > 6:
            file_type = "Compressed"

        else:
            file_type = "Normal"

    return entropy, file_type, block_var, header_valid, blocks

# ---------------- CONFIG ----------------

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

history_file = "scan_history.csv"

# ---------------- DASHBOARD ----------------

if page == "Dashboard":

    st.title("Hybrid Detection System")

    data = safe_read_csv(history_file)

    if not data.empty and "Type" in data.columns:

        encrypted = len(data[data["Type"].str.contains("Encrypted")])
        compressed = len(data[data["Type"].str.contains("Compressed")])
        normal = len(data[data["Type"].str.contains("Normal")])

    else:
        encrypted = compressed = normal = 0

    col1, col2, col3 = st.columns(3)

    col1.metric("Encrypted", encrypted)
    col2.metric("Compressed", compressed)
    col3.metric("Normal", normal)

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

            entropy, file_type, block_var, header_valid, blocks = analyze_file(uploaded_file.name)

            col1, col2, col3, col4 = st.columns(4)

            col1.metric("Entropy", round(entropy, 3))
            col2.metric("Detected Type", file_type)
            col3.metric("Block Variation", round(block_var, 3))
            col4.metric("Header Valid", header_valid)

            # -------- HEATMAP FOR IMAGES --------
            ext = os.path.splitext(uploaded_file.name)[1].lower()

            if ext in [".jpg", ".jpeg", ".png"]:

                st.subheader("Block-wise Entropy Heatmap")

                fig, ax = plt.subplots(figsize=(10, 3))

                heatmap_data = np.array(blocks).reshape(1, -1)

                im = ax.imshow(heatmap_data, aspect='auto')
                plt.colorbar(im, ax=ax, label="Entropy")

                ax.set_xlabel("Block Number")
                ax.set_ylabel("Entropy Distribution")
                ax.set_title("Image Block-wise Entropy Heatmap")

                st.pyplot(fig)

            # -------- SAVE HISTORY --------
            columns = ["File", "Entropy", "BlockVar", "Header", "Type"]

            history = pd.DataFrame([{
                "File": uploaded_file.name,
                "Entropy": entropy,
                "BlockVar": block_var,
                "Header": header_valid,
                "Type": file_type
            }])[columns]

            history.to_csv(
                history_file,
                mode="a",
                header=not os.path.exists(history_file),
                index=False,
                quoting=csv.QUOTE_MINIMAL
            )

# ---------------- ANALYTICS ----------------

elif page == "Analytics":

    st.header("System Analytics")

    data = safe_read_csv(history_file)

    if not data.empty:

        if "Entropy" in data.columns:
            st.subheader("Entropy Trend")
            st.line_chart(data["Entropy"])

        if "Type" in data.columns:
            st.subheader("File Type Distribution")
            st.bar_chart(data["Type"].value_counts())

    else:
        st.info("No valid data available")

# ---------------- HISTORY ----------------

elif page == "History":

    st.header("Detection History")

    data = safe_read_csv(history_file)

    if not data.empty:
        st.dataframe(data)
    else:
        st.info("No scans performed yet")

# ---------------- ABOUT ----------------

elif page == "About":

    st.header("About")

    st.write("""
    The Hybrid Detection System is a digital forensic tool designed to accurately identify normal, compressed, encrypted, and partially encrypted data using a combination of entropy analysis, file signature verification, and block-wise entropy analysis. This hybrid approach significantly reduces false positives and improves detection reliability.

    The system processes uploaded files, computes entropy metrics, evaluates structural integrity, and visualizes results through charts and heatmaps. It is particularly useful for digital forensic investigators, cybersecurity analysts, and researchers in detecting hidden or suspicious data.

    Key benefits include improved classification accuracy, support for partial encryption detection, reduced misclassification, and user-friendly visualization for decision-making.
    """)
