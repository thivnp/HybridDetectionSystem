import streamlit as st
import pandas as pd
import os
import math
import numpy as np
import matplotlib.pyplot as plt
import csv
from datetime import datetime

# ---------------- LOGIN SYSTEM ----------------

def login():
    st.title("🔐 Admin Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == "admin" and password == "Qaz@#1234":
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

# ---------------- SAFE CSV ----------------

def safe_read_csv(file):
    try:
        return pd.read_csv(file, on_bad_lines='skip')
    except:
        return pd.DataFrame()

# ---------------- ENTROPY ----------------

def calculate_entropy(data):
    if len(data) == 0:
        return 0

    entropy = 0
    for x in range(256):
        p_x = data.count(x)/len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)

    return entropy

# ---------------- BLOCK ENTROPY ----------------

def block_entropy(data, block_size=1024):
    return [calculate_entropy(data[i:i+block_size]) for i in range(0, len(data), block_size)]

# ---------------- SIGNATURE CHECK ----------------

def check_file_signature(data, filename):
    ext = os.path.splitext(filename)[1].lower()

    if ext in [".jpg", ".jpeg"]:
        return data[:3] == [255,216,255]
    elif ext == ".png":
        return data[:4] == [137,80,78,71]
    else:
        return True

# ---------------- HYBRID DETECTION ----------------

def analyze_file(filepath):

    with open(filepath,"rb") as f:
        data = list(f.read())

    entropy = calculate_entropy(data)
    blocks = block_entropy(data)

    block_var = max(blocks) - min(blocks) if blocks else 0
    header_valid = check_file_signature(data, filepath)

    ext = os.path.splitext(filepath)[1].lower()

    # IMAGE LOGIC
    if ext in [".jpg",".jpeg",".png"]:

        if not header_valid:
            file_type = "Partially Encrypted Image"

        elif block_var > 1.5:
            file_type = "Partially Encrypted Image"

        elif entropy > 7.966:
            file_type = "Encrypted Image"

        elif entropy > 7.956:
            file_type = "Compressed Image"

        else:
            file_type = "Normal Image"

    # TEXT LOGIC
    else:

        if block_var > 2:
            file_type = "Partially Encrypted"

        elif entropy > 7.5:
            file_type = "Encrypted"

        elif entropy > 6:
            file_type = "Compressed"

        else:
            file_type = "Normal"

    confidence = min(100, round((entropy / 8) * 100, 2))

    return entropy, file_type, block_var, header_valid, blocks, confidence

# ---------------- STREAMLIT CONFIG ----------------

st.set_page_config(page_title="Hybrid Detection System", layout="wide")

st.sidebar.title("Hybrid Detection System")

# Logout
if st.sidebar.button("Logout"):
    st.session_state["logged_in"] = False
    st.rerun()

page = st.sidebar.selectbox(
    "Navigation",
    ["Dashboard","File Detection","Analytics","History","About"]
)

history_file = "scan_history.csv"

# ---------------- DASHBOARD ----------------

if page == "Dashboard":

    st.title("Hybrid Detection Dashboard")

    data = safe_read_csv(history_file)

    if not data.empty:

        encrypted = len(data[data["Type"].str.contains("Encrypted", na=False)])
        compressed = len(data[data["Type"].str.contains("Compressed", na=False)])
        normal = len(data[data["Type"].str.contains("Normal", na=False)])

    else:
        encrypted = compressed = normal = 0

    col1,col2,col3 = st.columns(3)

    col1.metric("Encrypted Files", encrypted)
    col2.metric("Compressed Files", compressed)
    col3.metric("Normal Files", normal)

    chart_data = pd.DataFrame({
        "Type":["Encrypted","Compressed","Normal"],
        "Count":[encrypted,compressed,normal]
    })

    st.bar_chart(chart_data.set_index("Type"))

# ---------------- FILE DETECTION ----------------

elif page == "File Detection":

    st.header("Upload File")

    uploaded_file = st.file_uploader("Upload file")

    if uploaded_file:

        with open(uploaded_file.name,"wb") as f:
            f.write(uploaded_file.getbuffer())

        if st.button("Run Detection"):

            entropy,file_type,block_var,header_valid,blocks,confidence = analyze_file(uploaded_file.name)

            col1,col2,col3,col4,col5 = st.columns(5)

            col1.metric("Entropy", round(entropy,3))
            col2.metric("Type", file_type)
            col3.metric("Block Var", round(block_var,3))
            col4.metric("Header", header_valid)
            col5.metric("Confidence %", confidence)

            # Warning system
            if "Encrypted" in file_type:
                st.error("⚠️ High Risk File")
            elif "Partial" in file_type:
                st.warning("⚠️ Suspicious File")
            else:
                st.success("✅ Safe File")

            # Heatmap for images
            ext = os.path.splitext(uploaded_file.name)[1].lower()

            if ext in [".jpg",".jpeg",".png"]:

                st.subheader("Block Entropy Heatmap")

                fig, ax = plt.subplots(figsize=(10,3))

                heat = np.array(blocks).reshape(1,-1)
                im = ax.imshow(heat, aspect='auto')

                plt.colorbar(im, ax=ax, label="Entropy")

                ax.set_xlabel("Block Index")
                ax.set_ylabel("Entropy Distribution")
                ax.set_title("Image Entropy Heatmap")

                st.pyplot(fig)

            # Save history
            df = pd.DataFrame([{
                "File": uploaded_file.name,
                "Entropy": entropy,
                "BlockVar": block_var,
                "Header": header_valid,
                "Type": file_type,
                "Confidence": confidence,
                "Timestamp": datetime.now()
            }])

            df.to_csv(
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

        st.subheader("Entropy Trend")
        st.line_chart(data["Entropy"])

        st.subheader("File Type Distribution")
        st.bar_chart(data["Type"].value_counts())

    else:
        st.info("No data available")

# ---------------- HISTORY ----------------

elif page == "History":

    st.header("Detection History")

    data = safe_read_csv(history_file)

    if not data.empty:

        st.write(f"Total Records: {len(data)}")

        # Pagination
        rows_per_page = 10
        total_pages = max(1, len(data)//rows_per_page + 1)

        page_num = st.number_input("Page", min_value=1, max_value=total_pages, step=1)

        start = (page_num - 1) * rows_per_page
        end = start + rows_per_page

        st.dataframe(data.iloc[start:end], use_container_width=True)

        # Download
        csv_download = data.to_csv(index=False).encode()
        st.download_button("Download Full History", csv_download, "history.csv", "text/csv")

        # Clear history
        if st.button("Clear History"):
            os.remove(history_file)
            st.success("History Cleared")
            st.rerun()

    else:
        st.info("No scans performed yet")

# ---------------- ABOUT ----------------

elif page == "About":

    st.header("About")

    st.write("""
    The Hybrid Detection System is a digital forensic tool designed to accurately identify and classify different types of data, including normal, compressed, encrypted, and partially encrypted files. It employs a hybrid approach that integrates entropy analysis, file signature verification, and block-wise entropy analysis to enhance detection accuracy while minimizing false positives. The system follows a structured workflow that begins with file upload and preprocessing, followed by entropy computation and structural validation. These results are then processed through a hybrid classification mechanism to determine the nature of the data. To support better understanding and interpretation, the system presents its findings through visualizations—using heatmaps for image-based analysis and statistical outputs for text-based data. Overall, this system is intended to assist digital forensic investigators, cybersecurity analysts, and law enforcement agencies in efficiently analyzing and classifying data during forensic investigations.
    """)
