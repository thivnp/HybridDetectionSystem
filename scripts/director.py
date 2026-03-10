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
import zipfile

# -----------------------------
# INTERNATIONAL FORENSIC STANDARDS
# -----------------------------
# Standard Text/Doc files usually sit between 3.5 and 5.0
# Compressed Images (JPG) sit between 7.2 and 7.8
# Encrypted data is mathematically designed to be > 7.95
TEXT_THRESHOLD = 7.5
IMAGE_THRESHOLD = 7.98 
BLOCK_SIZE = 1024

st.set_page_config(page_title="Forensic Hybrid Detector", layout="wide")

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

def simulate_encryption(data):
    # PBKDF2 for simulation purposes
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=48, salt=b"forensic", iterations=100000, backend=default_backend())
    key_iv = kdf.derive(b"password")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key_iv[:32]), modes.CBC(key_iv[32:]), backend=default_backend())
    return cipher.encryptor().update(padded) + cipher.finalize()

# -----------------------------
# UI DESIGN
# -----------------------------
st.title("🔐 Multi-Threshold Forensic Entropy Analyst")

col_side, col_main = st.columns([1, 3])

with col_side:
    st.subheader("Analysis Settings")
    file_mode = st.radio("File Type:", ["Text/Document", "Image/Compressed"])
    uploaded_file = st.file_uploader("Upload File", type=None)

if uploaded_file:
    file_bytes = uploaded_file.read()
    overall_ent = calculate_entropy(file_bytes)
    
    # Apply correct International Threshold based on mode
    current_threshold = IMAGE_THRESHOLD if file_mode == "Image/Compressed" else TEXT_THRESHOLD
    
    # -----------------------------
    # DETECTION & POPUPS
    # -----------------------------
    if overall_ent >= current_threshold:
        st.error(f"🚨 ENCRYPTED DATA DETECTED (Entropy: {overall_ent:.4f})")
        st.toast("Forensic Alert: Encrypted Signature Found", icon="🔒")
        classification = "Encrypted"
    elif overall_ent > (current_threshold - 0.5):
        st.warning(f"⚠️ PARTIAL ENCRYPTION / COMPRESSED (Entropy: {overall_ent:.4f})")
        st.toast("Forensic Note: High Entropy / Compressed", icon="📂")
        classification = "Partial/Compressed"
    else:
        st.success(f"✅ NORMAL DATA DETECTED (Entropy: {overall_ent:.4f})")
        st.toast("Forensic Match: Normal File", icon="📄")
        classification = "Normal"

    # -----------------------------
    # VISUALIZATION (Main Panel)
    # -----------------------------
    with col_main:
        tabs = st.tabs(["📊 Entropy Contrast", "🌡️ Heatmap Analysis", "📝 Forensic Report"])
        
        # TAB 1: Comparison Graph
        with tabs[0]:
            st.subheader("Comparison Against Simulations")
            sim_enc = simulate_encryption(file_bytes)
            
            comparison_labels = ["Uploaded File", "Normal (Simulated)", "Encrypted (Simulated)"]
            comparison_values = [overall_ent, 4.5 if file_mode == "Text/Document" else 7.4, calculate_entropy(sim_enc)]
            
            fig, ax = plt.subplots(figsize=(10, 4))
            colors = ['#4b8bff', '#8ac926', '#ff4b4b']
            ax.bar(comparison_labels, comparison_values, color=colors)
            ax.axhline(y=current_threshold, color='red', linestyle='--', label=f"Threshold ({current_threshold})")
            ax.set_ylim(0, 8.5)
            ax.legend()
            st.pyplot(fig)

        # TAB 2: Image Heatmap
        with tabs[1]:
            st.subheader("Block-wise Entropy Heatmap")
            block_data = get_block_entropy(file_bytes)
            
            # Formatting data for heatmap
            dimension = int(math.sqrt(len(block_data)))
            if dimension > 1:
                heatmap_array = np.array(block_data[:dimension**2]).reshape(dimension, dimension)
                fig_heat, ax_heat = plt.subplots()
                im = ax_heat.imshow(heatmap_array, cmap='viridis', aspect='auto')
                plt.colorbar(im, label="Entropy Strength")
                ax_heat.set_title("Visual Signature of Data Density")
                st.pyplot(fig_heat)
                
                st.info("💡 Tip: A uniform, bright heatmap indicates full encryption. A varied heatmap indicates a normal image structure.")
            else:
                st.write("File too small for heatmap analysis.")

        # TAB 3: Metadata
        with tabs[2]:
            st.json({
                "Filename": uploaded_file.name,
                "Size (Bytes)": len(file_bytes),
                "Calculated Entropy": overall_ent,
                "Forensic Classification": classification,
                "Applied Threshold": current_threshold
            })

    # Download Button
    st.download_button("📥 Download Report", 
                       pd.DataFrame([{"Metric": "Entropy", "Value": overall_ent}]).to_csv(), 
                       "forensic_report.csv")
