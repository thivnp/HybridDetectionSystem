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
# International Standards: Encrypted data is almost always > 7.98
TEXT_THRESHOLD = 7.0
IMAGE_THRESHOLD = 7.98 

st.set_page_config(page_title="Image & Text Forensic Analyst", layout="wide")

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
    """Detects if a high-entropy file is actually a legitimate image."""
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
st.title("🔐 Advanced Forensic Data Classifier")
st.sidebar.header("Analysis Parameters")
file_mode = st.sidebar.radio("File Category:", ["Text/Document", "Image/Compressed"])

uploaded_file = st.file_uploader("Upload File for Forensic Scan", type=None)

if uploaded_file:
    file_bytes = uploaded_file.read()
    overall_ent = calculate_entropy(file_bytes)
    file_sig = check_file_signatures(file_bytes)
    
    # Logic to prevent Image False Positives
    is_encrypted = False
    status_msg = ""
    
    if file_mode == "Image/Compressed":
        # If it has a signature, it's normal regardless of high entropy
        if file_sig:
            is_encrypted = False
            status_msg = f"✅ Normal {file_sig} Image Detected (Entropy: {overall_ent:.4f})"
            st.success(status_msg)
            classification = "Normal Image"
        elif overall_ent >= IMAGE_THRESHOLD:
            is_encrypted = True
            status_msg = f"🚨 Encrypted Image/Blob Detected (Entropy: {overall_ent:.4f})"
            st.error(status_msg)
            classification = "Encrypted"
        else:
            status_msg = f"⚠️ Partially Encrypted or Low-Quality Image (Entropy: {overall_ent:.4f})"
            st.warning(status_msg)
            classification = "Partial/Suspicious"
    else:
        # Text Mode Logic
        if overall_ent >= TEXT_THRESHOLD:
            st.error(f"🚨 Encrypted Text/Doc Detected (Entropy: {overall_ent:.4f})")
            classification = "Encrypted"
        elif overall_ent > 6.0:
            st.warning(f"⚠️ Partially Encrypted Text Detected (Entropy: {overall_ent:.4f})")
            classification = "Partial"
        else:
            st.success(f"✅ Normal Text Document (Entropy: {overall_ent:.4f})")
            classification = "Normal"

    st.toast(classification, icon="🔍")

    # -----------------------------
    # GRAPHICAL VIEW
    # -----------------------------
    st.divider()
    
    if file_mode == "Image/Compressed":
        st.subheader("Structural Entropy Heatmap")
        st.write("Visualizing data density distribution. Uniform color = Encryption | Patterned color = Normal.")
        
        block_data = get_block_entropy(file_bytes)
        dim = int(math.sqrt(len(block_data)))
        
        if dim >= 2:
            heatmap_array = np.array(block_data[:dim**2]).reshape(dim, dim)
            fig, ax = plt.subplots(figsize=(8, 6))
            # 'magma' or 'viridis' provide high contrast for forensics
            im = ax.imshow(heatmap_array, cmap='magma', aspect='equal', interpolation='nearest')
            plt.colorbar(im, label="Entropy Level (0-8)")
            ax.set_xticks([])
            ax.set_yticks([])
            st.pyplot(fig)
        else:
            st.info("File too small for heatmap. Use Text mode for small files.")
    
    else:
        # Bar Chart only for Text mode
        st.subheader("Entropy Analysis")
        fig, ax = plt.subplots(figsize=(10, 2))
        ax.barh(["Uploaded File"], [overall_ent], color='#4b8bff')
        ax.axvline(TEXT_THRESHOLD, color='red', linestyle='--', label="Threshold")
        ax.set_xlim(0, 8.5)
        ax.legend()
        st.pyplot(fig)

    # Metadata Summary
    with st.expander("View Forensic Metadata"):
        st.json({
            "Filename": uploaded_file.name,
            "Entropy": overall_ent,
            "Signature Match": file_sig if file_sig else "None",
            "Classification": classification
        })
