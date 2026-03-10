import streamlit as st
import matplotlib.pyplot as plt
import numpy as np
import math
import io
import pandas as pd
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# -----------------------------
# FORENSIC CONFIGURATION
# -----------------------------
BLOCK_SIZE = 1024
TEXT_THRESHOLD = 7.0
IMAGE_THRESHOLD = 7.98 

st.set_page_config(page_title="Forensic Data Analyst", layout="wide")

# -----------------------------
# CORE UTILITIES
# -----------------------------

def calculate_entropy(data):
    if not data: return 0
    freq = [0] * 256
    for b in data: freq[b] += 1
    ent = 0
    for f in freq:
        if f > 0:
            p = f / len(data)
            ent -= p * math.log2(p)
    return ent

def get_block_entropy(data):
    return [calculate_entropy(data[i:i+BLOCK_SIZE]) for i in range(0, len(data), BLOCK_SIZE)]

def check_file_signatures(data):
    signatures = {
        b'\xff\xd8\xff': "JPEG",
        b'\x89PNG\r\n\x1a\n': "PNG",
        b'GIF87a': "GIF",
        b'GIF89a': "GIF",
        b'RIFF': "WebP/Media"
    }
    for sig, name in signatures.items():
        if data.startswith(sig):
            return name
    return None

# -----------------------------
# MAIN UI
# -----------------------------
st.title("Universal Forensic Entropy Analyst")
st.sidebar.header("Analysis Settings")
file_mode = st.sidebar.radio("File Category:", ["Text/Document", "Image/Compressed"])

uploaded_file = st.file_uploader("Upload File for Forensic Scan", type=None)

if uploaded_file:
    file_bytes = uploaded_file.read()
    overall_ent = calculate_entropy(file_bytes)
    file_sig = check_file_signatures(file_bytes)
    
    # -----------------------------
    # DETECTION LOGIC (POPUPS)
    # -----------------------------
    if file_mode == "Image/Compressed":
        if file_sig:
            classification = f"Normal {file_sig} Image"
            st.success(f"✅ {classification} Detected (Entropy: {overall_ent:.4f})")
        elif overall_ent >= IMAGE_THRESHOLD:
            classification = "Encrypted Image/Blob"
            st.error(f"🚨 {classification} Detected (Entropy: {overall_ent:.4f})")
        else:
            classification = "Partial/Suspicious Image"
            st.warning(f"⚠️ {classification} (Entropy: {overall_ent:.4f})")
    else:
        if overall_ent >= TEXT_THRESHOLD:
            classification = "Encrypted Text/Doc"
            st.error(f"🚨 {classification} Detected (Entropy: {overall_ent:.4f})")
        elif overall_ent > 6.0:
            classification = "Partial Encrypted Text"
            st.warning(f"⚠️ {classification} (Entropy: {overall_ent:.4f})")
        else:
            classification = "Normal Text Document"
            st.success(f"✅ {classification} (Entropy: {overall_ent:.4f})")

    st.toast(classification, icon="🔍")

    # -----------------------------
    # VISUALIZATION & DOWNLOADS
    # -----------------------------
    st.divider()
    
    # Create a buffer for the plot to enable downloading
    plot_buffer = io.BytesIO()

    if file_mode == "Image/Compressed":
        st.subheader("Structural Entropy Heatmap")
        block_data = get_block_entropy(file_bytes)
        dim = int(math.sqrt(len(block_data)))
        
        if dim >= 2:
            heatmap_array = np.array(block_data[:dim**2]).reshape(dim, dim)
            fig, ax = plt.subplots(figsize=(7, 5))
            im = ax.imshow(heatmap_array, cmap='magma', aspect='equal')
            plt.colorbar(im, label="Entropy Strength")
            ax.set_title(f"Heatmap: {uploaded_file.name}")
            st.pyplot(fig)
            
            # Save plot to buffer
            fig.savefig(plot_buffer, format='png')
        else:
            st.warning("File too small for heatmap analysis.")
    
    else:
        st.subheader("Entropy Distribution Chart")
        fig, ax = plt.subplots(figsize=(10, 3))
        ax.barh(["Uploaded File"], [overall_ent], color='#4b8bff')
        ax.axvline(TEXT_THRESHOLD, color='red', linestyle='--', label="Threshold")
        ax.set_xlim(0, 8.5)
        ax.set_title(f"Analysis: {uploaded_file.name}")
        ax.legend()
        st.pyplot(fig)
        
        # Save plot to buffer
        fig.savefig(plot_buffer, format='png')

    # -----------------------------
    # DOWNLOAD SECTION
    # -----------------------------
    st.write("###Export Analysis Results")
    dl_col1, dl_col2 = st.columns(2)

    # 1. CSV Report Download
    report_df = pd.DataFrame([{
        "Filename": uploaded_file.name,
        "Entropy": round(overall_ent, 6),
        "Classification": classification,
        "Magic Byte Signature": file_sig if file_sig else "None",
        "Analysis Mode": file_mode
    }])
    csv_data = report_df.to_csv(index=False).encode('utf-8')

    with dl_col1:
        st.download_button(
            label="Download CSV Report",
            data=csv_data,
            file_name=f"Forensic_Report_{uploaded_file.name}.csv",
            mime="text/csv"
        )

    # 2. Graph/Heatmap Download
    with dl_col2:
        if plot_buffer.getbuffer().nbytes > 0:
            st.download_button(
                label="Download Visualization (PNG)",
                data=plot_buffer.getvalue(),
                file_name=f"Forensic_Graph_{uploaded_file.name}.png",
                mime="image/png"
            )

