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
# Text/Docs: Low entropy (3.5 - 5.0). Threshold 7.0 is safe.
# Images (JPG/PNG): Naturally high (7.2 - 7.8). Threshold must be > 7.9.
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
    # Ensure we don't return an empty list for small files
    blocks = [calculate_entropy(data[i:i+BLOCK_SIZE]) for i in range(0, len(data), BLOCK_SIZE)]
    return blocks if blocks else [0]

def simulate_encryption(data):
    """Corrected AES Encryption logic to prevent AttributeError"""
    try:
        # 1. Key Derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), 
            length=48, 
            salt=b"forensic_salt", 
            iterations=100000, 
            backend=default_backend()
        )
        key_iv = kdf.derive(b"password123")
        
        # 2. Padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # 3. Cipher Setup
        cipher = Cipher(
            algorithms.AES(key_iv[:32]), 
            modes.CBC(key_iv[32:]), 
            backend=default_backend()
        )
        
        # 4. Correct Encryptor Object usage
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext
    except Exception as e:
        # Fallback if encryption fails (e.g. empty data)
        return data

# -----------------------------
# UI LAYOUT
# -----------------------------
st.title("🔐 Multi-Threshold Forensic Entropy Analyst")
st.markdown("### Detects Encrypted, Partially Encrypted, and Compressed Data")

col_side, col_main = st.columns([1, 3])

with col_side:
    st.subheader("Analysis Settings")
    file_mode = st.radio("Select Analysis Mode:", ["Text/Document", "Image/Compressed"])
    uploaded_file = st.file_uploader("Upload Target File", type=None)
    st.info(f"Current Mode: {file_mode}\nThreshold: {IMAGE_THRESHOLD if file_mode == 'Image/Compressed' else TEXT_THRESHOLD}")

if uploaded_file:
    file_bytes = uploaded_file.read()
    overall_ent = calculate_entropy(file_bytes)
    
    # Selection of threshold based on user mode
    current_threshold = IMAGE_THRESHOLD if file_mode == "Image
