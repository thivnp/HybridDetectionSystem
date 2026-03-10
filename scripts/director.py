import streamlit as st
import matplotlib.pyplot as plt
import numpy as np
import os
import math
import io
import pandas as pd
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import zipfile

# -----------------------------
# CONFIGURATION
# -----------------------------
BLOCK_SIZE = 1024
THRESHOLD_ENCRYPTED = 7.9  # Encrypted data is almost perfectly random
THRESHOLD_COMPRESSED = 7.2 # Compressed data is high but lower than encryption
PASSWORD = b"forensicpassword123"
SALT     = b"saltysalt12345678"

st.set_page_config(page_title="Universal Forensic Detector", layout="wide")

# -----------------------------
# CORE LOGIC FUNCTIONS
# -----------------------------

def calculate_entropy(data):
    if not data: return 0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0
    for f in freq:
        if f > 0:
            p = f / len(data)
            ent -= p * math.log2(p)
    return ent

def derive_key_iv(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=48, salt=salt, iterations=100000, backend=default_backend())
    key_iv = kdf.derive(password)
    return key_iv[:32], key_iv[32:]

def safe_encrypt(data):
    try:
        key, iv = derive_key_iv(PASSWORD, SALT)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        return cipher.encryptor().update(padded) + cipher.finalize()
    except:
        return data # Fallback

def safe_compress(data):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("file", data)
    return buf.getvalue()

# -----------------------------
# UI DESIGN
# -----------------------------
st.title("🔐 Universal Forensic Entropy Analyst")
st.markdown("Upload any file (Normal, Encrypted, or Compressed) to detect its state.")

uploaded_file = st.file_uploader("Upload target file", type=None)

if uploaded_file:
    # 1. READ FILE
    file_bytes = uploaded_file.read()
    file_size = len(file_bytes)
    overall_ent = calculate_entropy(file_bytes)
    
    # 2. FILE SIGNATURE CHECK (Magic Bytes)
    # This detects if a file claims to be a JPG/PNG but might be encrypted
    is_image = file_bytes.startswith((b'\xff\xd8\xff', b'\x89PNG', b'\x47\x49\x46\x38'))
    is_zip = file_bytes.startswith((b'PK\x03\x04', b'\x1f\x8b\x08'))

    # 3. DETECTION & POPUP LOGIC
    # We use a nested logic to ensure accuracy
    if overall_ent >= THRESHOLD_ENCRYPTED:
        detection_msg = "🚨 HIGH ALERT: This file is ENCRYPTED (or very strongly randomized)."
        st.error(detection_msg)
        st.toast(detection_msg, icon="🔒")
        classification = "Encrypted"
    elif overall_ent >= THRESHOLD_COMPRESSED:
        if is_image or is_zip:
            detection_msg = "ℹ️ NOTICE: This is a Normal Compressed File (Image/Archive)."
            st.info(detection_msg)
            classification = "Normal (Compressed)"
        else:
            detection_msg = "⚠️ WARNING: High Entropy detected. Could be Partial Encryption."
            st.warning(detection_msg)
            classification = "Partial/Suspicious"
        st.toast(detection_msg, icon="📂")
    else:
        detection_msg = "✅ NOTICE: This is a Normal Unencrypted/Plaintext file."
        st.success(detection_msg)
        st.toast(detection_msg, icon="📄")
        classification = "Normal (Plain)"

    # 4. GENERATE CONTRAST DATA FOR THE GRAPH
    # We show what this specific file would look like in other states
    contrast_data = {
        "Uploaded File": file_bytes,
        "If Compressed": safe_compress(file_bytes),
        "If Partial Enc": file_bytes[:file_size//2] + safe_encrypt(file_bytes[file_size//2:]),
        "If Full Enc": safe_encrypt(file_bytes)
    }
    
    names = list(contrast_data.keys())
    entropies = [calculate_entropy(v) for v in contrast_data.values()]

    # 5. VISUALIZATION
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Entropy Comparison Chart")
        fig, ax = plt.subplots(figsize=(10, 5))
        colors = ['#ff4b4b', '#4b8bff', '#ffca3a', '#8ac926']
        bars = ax.bar(names, entropies, color=colors)
        
        # Draw Threshold Lines
        ax.axhline(y=THRESHOLD_ENCRYPTED, color='red', linestyle='--', alpha=0.5, label="Encryption Threshold")
        ax.axhline(y=THRESHOLD_COMPRESSED, color='orange', linestyle='--', alpha=0.5, label="Compression Threshold")
        
        ax.set_ylim(0, 8.5)
        ax.set_ylabel("Entropy (Bits per Byte)")
        ax.legend(loc='lower right')
        st.pyplot(fig)

    with col2:
        st.subheader("Data Summary")
        st.write(f"**Filename:** {uploaded_file.name}")
        st.write(f"**Detected Type:** {classification}")
        st.write(f"**Overall Entropy:** {overall_ent:.4f}")
        
        # Metrics for visual pop
        st.metric("Analyzed Entropy", f"{overall_ent:.2f}", delta=f"{overall_ent - 7.5:.2f}" if overall_ent > 7.5 else None)

    # 6. BLOCK ANALYSIS (For Images/Structure)
    st.divider()
    st.subheader("Internal Structure Analysis (Block Entropy)")
    
    blocks = [calculate_entropy(file_bytes[i:i+BLOCK_SIZE]) for i in range(0, len(file_bytes), BLOCK_SIZE)]
    
    fig2, ax2 = plt.subplots(figsize=(12, 3))
    ax2.plot(blocks, color='#4b8bff', linewidth=1)
    ax2.fill_between(range(len(blocks)), blocks, color='#4b8bff', alpha=0.2)
    ax2.set_title("Entropy Signature across File Blocks")
    ax2.set_xlabel("Block Index")
    ax2.set_ylabel("Entropy")
    st.pyplot(fig2)

    # 7. DOWNLOAD REPORT
    report_df = pd.DataFrame({
        "Analysis Metric": ["Filename", "Size", "Detected Classification", "Shannon Entropy"],
        "Value": [uploaded_file.name, f"{file_size} bytes", classification, overall_ent]
    })
    st.download_button("📥 Download Forensic Report", report_df.to_csv(index=False), "forensic_report.csv", "text/csv")
