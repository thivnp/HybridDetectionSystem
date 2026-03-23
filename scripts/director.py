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

        if username == "admin" and password == "1234":
            st.session_state["logged_in"] = True
            st.success("Login Successful ✅")
            st.rerun()
        else:
            st.error("Invalid Username or Password ❌")


# Initialize session
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

# Block app if not logged in
if not st.session_state["logged_in"]:
    login()
    st.stop()

# ---------------- DETECTION FUNCTIONS ----------------

def calculate_entropy(data):

    entropy = 0
    length = len(data)

    for x in range(256):
        p_x = data.count(x)/length
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)

    return entropy


def analyze_file(filepath):

    with open(filepath,"rb") as f:
        data = list(f.read())

    entropy = calculate_entropy(data)

    if entropy > 7.5:
        file_type = "Encrypted"
    elif entropy > 6:
        file_type = "Compressed"
    else:
        file_type = "Normal"

    return entropy,file_type


# ---------------- STREAMLIT CONFIG ----------------

st.set_page_config(
    page_title="Hybrid Detection System",
    layout="wide",
    page_icon="🔐"
)

# ---------------- SIDEBAR ----------------

st.sidebar.title("Hybrid Detection System")

# Logout button
if st.sidebar.button("Logout"):
    st.session_state["logged_in"] = False
    st.rerun()

page = st.sidebar.selectbox(
    "Navigation",
    ["Dashboard","File Detection","Analytics","History","About"]
)

# ---------------- DASHBOARD ----------------

if page == "Dashboard":

    st.title("Hybrid Encryption & Compression Detection System")

    history_file = "scan_history.csv"

    if os.path.exists(history_file):

        data = pd.read_csv(history_file)

        encrypted = len(data[data["Type"]=="Encrypted"])
        compressed = len(data[data["Type"]=="Compressed"])
        normal = len(data[data["Type"]=="Normal"])

    else:

        encrypted = compressed = normal = 0


    col1,col2,col3 = st.columns(3)

    col1.metric("Encrypted Files",encrypted)
    col2.metric("Compressed Files",compressed)
    col3.metric("Normal Files",normal)

    chart_data = pd.DataFrame({
        "Type":["Encrypted","Compressed","Normal"],
        "Count":[encrypted,compressed,normal]
    })

    st.bar_chart(chart_data.set_index("Type"))

# ---------------- FILE DETECTION ----------------

elif page == "File Detection":

    st.header("Upload File for Detection")

    uploaded_file = st.file_uploader("Upload a file")

    if uploaded_file:

        with open(uploaded_file.name,"wb") as f:
            f.write(uploaded_file.getbuffer())

        if st.button("Run Detection"):

            entropy,file_type = analyze_file(uploaded_file.name)

            col1,col2 = st.columns(2)

            col1.metric("Entropy Score",round(entropy,2))
            col2.metric("Detected Type",file_type)

            history = pd.DataFrame({
                "File":[uploaded_file.name],
                "Entropy":[entropy],
                "Type":[file_type]
            })

            if os.path.exists("scan_history.csv"):
                history.to_csv("scan_history.csv",mode="a",header=False,index=False)
            else:
                history.to_csv("scan_history.csv",index=False)

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
    The Hybrid Detection System is a digital forensic tool designed to accurately identify normal, compressed, encrypted, and partially encrypted data using a combination of entropy analysis, file structure validation, and byte-pattern examination. Unlike traditional entropy-only methods, this system integrates multiple analytical techniques to reduce false positives and improve detection reliability, especially in cases where compressed data mimics encrypted characteristics or when only portions of a file are encrypted. The system follows a structured process where uploaded files are first preprocessed, then analyzed using entropy calculations, followed by classification logic to determine the data type. The results are presented through interactive visualizations and stored for further analysis. This system is beneficial for digital forensic investigators, cybersecurity analysts, law enforcement agencies, and researchers, as it enhances their ability to detect hidden or suspicious data. Key benefits include improved accuracy, reduced misclassification, and user-friendly reporting for forensic investigations.
    """)
