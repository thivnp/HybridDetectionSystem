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

        elif entropy > 7.9:
            file_type = "Encrypted Image"

        elif entropy > 7.5:
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

# ---------------- STREAMLIT ----------------

st.set_page_config(page_title="Hybrid Detection System", layout="wide")

st.sidebar.title("Hybrid Detection System")

if st.sidebar.button("Logout"):
    st.session_state["logged_in"] = False
    st.rerun()

page = st.sidebar.selectbox("Navigation",
["Dashboard","File Detection","Analytics","History","About"])

history_file = "scan_history.csv"

# ---------------- FILE DETECTION ----------------

if page == "File Detection":

    st.header("Upload File")

    uploaded_file = st.file_uploader("Upload file")

    if uploaded_file:

        with open(uploaded_file.name,"wb") as f:
            f.write(uploaded_file.getbuffer())

        if st.button("Run Detection"):

            entropy,file_type,block_var,header_valid,blocks,confidence = analyze_file(uploaded_file.name)

            col1,col2,col3,col4,col5 = st.columns(5)

            col1.metric("Entropy",round(entropy,3))
            col2.metric("Type",file_type)
            col3.metric("Block Var",round(block_var,3))
            col4.metric("Header",header_valid)
            col5.metric("Confidence %",confidence)

            # WARNING SYSTEM
            if "Encrypted" in file_type:
                st.error("⚠️ High Risk File")
            elif "Partial" in file_type:
                st.warning("⚠️ Suspicious File")
            else:
                st.success("✅ Safe File")

            # HEATMAP FOR IMAGES
            ext = os.path.splitext(uploaded_file.name)[1].lower()

            if ext in [".jpg",".jpeg",".png"]:

                st.subheader("Block Entropy Heatmap")

                fig,ax = plt.subplots(figsize=(10,3))

                heat = np.array(blocks).reshape(1,-1)

                im = ax.imshow(heat,aspect='auto')
                plt.colorbar(im,ax=ax,label="Entropy")

                ax.set_xlabel("Block Index")
                ax.set_ylabel("Entropy Distribution")
                ax.set_title("Image Entropy Heatmap")

                st.pyplot(fig)

            # SAVE HISTORY
            df = pd.DataFrame([{
                "File":uploaded_file.name,
                "Entropy":entropy,
                "BlockVar":block_var,
                "Header":header_valid,
                "Type":file_type,
                "Confidence":confidence,
                "Timestamp":datetime.now()
            }])

            df.to_csv(history_file,mode="a",
                      header=not os.path.exists(history_file),
                      index=False, quoting=csv.QUOTE_MINIMAL)

# ---------------- ABOUT ----------------

elif page == "About":

    st.header("About")

    st.write("""
    The Hybrid Detection System is a digital forensic tool designed to accurately identify normal, compressed, encrypted, and partially encrypted data using a combination of entropy analysis, file signature verification, and block-wise entropy analysis. This hybrid approach significantly reduces false positives and improves detection reliability.

    The system processes uploaded files, computes entropy metrics, evaluates structural integrity, and visualizes results through charts and heatmaps. It is particularly useful for digital forensic investigators, cybersecurity analysts, and researchers in detecting hidden or suspicious data.

    Key benefits include improved classification accuracy, support for partial encryption detection, reduced misclassification, and user-friendly visualization for decision-making.
    """)
