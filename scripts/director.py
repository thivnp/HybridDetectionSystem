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
import binascii

# -----------------------------
# INTERNATIONAL FORENSIC STANDARDS
# -----------------------------
TEXT_THRESHOLD = 7.0
IMAGE_THRESHOLD = 7.95 
BLOCK_SIZE = 1024

st.set_page_config(page_title="Forensic Hybrid Detector", layout="wide")

# -----------------------------
# STABLE CORE UTILITIES
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
    blocks = [calculate_entropy(data[i:i+BLOCK_SIZE]) for i in range(0, len(data), BLOCK_SIZE)]
    return blocks if blocks else [0]

def simulate_encryption(data):
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), 
            length=48, 
            salt=b"forensic_salt", 
            iterations=100000, 
            backend=default_backend()
        )
        key_iv = kdf.derive(b"password123")
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key_iv[:32]), modes.CBC(key_iv[32:]), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()
    except:
        return data

# -----------------------------
# UI LAYOUT
# -----------------------------
st.title("🔐 Multi-Threshold Forensic Entropy Analyst")

col_side, col_main = st.columns([1, 3])

with col_side:
    st.subheader("Analysis Settings")
    file_mode = st.radio("Select Analysis Mode:", ["Text/Document", "Image/Compressed"])
    uploaded_file = st.file_uploader("Upload Target File", type=None)

if uploaded_file:
    file_bytes = uploaded_file.read()
    overall_ent = calculate_entropy(file_bytes)
    
    # Selection of threshold based on user mode
    current_threshold = IMAGE_THRESHOLD if file_mode == "Image/Compressed" else TEXT_THRESHOLD
    
    # -----------------------------
    # DETECTION & NOTIFICATIONS
    # -----------------------------
    if overall_ent >= current_threshold:
        st.error(f"🚨 ENCRYPTED DATA DETECTED (Entropy: {overall_ent:.4f})")
        st.toast("Forensic Alert: Encrypted Signature Found", icon="🔒")
        classification = "Encrypted"
    elif overall_ent > (current_threshold - 0.6):
        st.warning(f"⚠️ PARTIAL ENCRYPTION / HIGHLY COMPRESSED (Entropy: {overall_ent:.4f})")
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
        tabs = st.tabs(["📊 Entropy Contrast", "🌡️ Heatmap Analysis", "🔍 Hex Preview"])
        
        with tabs[0]:
            st.subheader("Comparison Against Simulations")
            sim_enc = simulate_encryption(file_bytes)
            base_normal = 4.2 if file_mode == "Text/Document" else 7.4
            
            comparison_labels = ["Uploaded File", "Normal Baseline", "Simulated Encrypted"]
            comparison_values = [overall_ent, base_normal, calculate_entropy(sim_enc)]
            
            fig, ax = plt.subplots(figsize=(10, 4))
            ax.bar(comparison_labels, comparison_values, color=['#4b8bff', '#8ac926', '#ff4b4b'])
            ax.axhline(y=current_threshold, color='red', linestyle='--', label=f"Threshold ({current_threshold})")
            ax.set_ylim(0, 8.5)
            ax.legend()
            st.pyplot(fig)

        with tabs[1]:
            st.subheader("Structural Entropy Heatmap")
            block_data = get_block_entropy(file_bytes)
            dim = int(math.sqrt(len(block_data)))
            
            if dim >= 2:
                heatmap_array = np.array(block_data[:dim**2]).reshape(dim, dim)
                fig_heat, ax_heat = plt.subplots()
                im = ax_heat.imshow(heatmap_array, cmap='magma', aspect='auto')
                plt.colorbar(im, label="Entropy Strength")
                st.pyplot(fig_heat)
            else:
                st.warning("File too small for heatmap.")

        with tabs[2]:
            st.subheader("File Header (Hex)")
            hex_data = binascii.hexlify(file_bytes[:128]).decode('utf-8')
            formatted_hex = " ".join(hex_data[i:i+2] for i in range(0, len(hex_data), 2))
            st.code(formatted_hex, language='text')
            st.info("Tip: If you see 'FF D8 FF' (JPEG) or '89 50 4E 47' (PNG) here, the file is a normal image, even if entropy is high.")

    # CSV Download
    report_data = {"Filename": uploaded_file.name, "Entropy": overall_ent, "Result": classification}
    st.download_button("📥 Download Report", pd.DataFrame([report_data]).to_csv(index=False), "report.csv")
