# Save as dashboard.py
# Run via: streamlit run dashboard.py

import streamlit as st
import matplotlib.pyplot as plt
import numpy as np
import os
import math
import io
import tempfile
import pandas as pd
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import zipfile

BLOCK_SIZE = 1024
THRESHOLD  = 7.3
PASSWORD = b"forensicpassword123"
SALT     = b"saltysalt12345678"

# Reports folder
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "../reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def derive_key_iv(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=48,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key_iv = kdf.derive(password)
    return key_iv[:32], key_iv[32:]

key, iv = derive_key_iv(PASSWORD, SALT)

def aes_encrypt(data, key, iv):
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()

def encrypt_second_half(data, key, iv):
    mid = len(data) // 2
    first = data[:mid]
    second = aes_encrypt(data[mid:], key, iv)
    return first + second

def calculate_entropy(data):
    if not data:
        return 0
    freq = [0]*256
    for b in data:
        freq[b] += 1
    ent = 0
    for f in freq:
        if f > 0:
            p = f / len(data)
            ent -= p * math.log2(p)
    return ent

def block_entropy(data):
    return [calculate_entropy(data[i:i+BLOCK_SIZE]) for i in range(0, len(data), BLOCK_SIZE)]

def compress_file_bytes(data, filename=None):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        name = os.path.basename(filename) if filename else "file"
        zf.writestr(name, data)
    return buffer.getvalue()

def generate_versions(file_path, label):
    with open(file_path, "rb") as f:
        original = f.read()
    versions = {}
    versions[f"{label}-Normal"] = original
    versions[f"{label}-Compressed"] = compress_file_bytes(original, file_path)
    versions[f"{label}-Encrypted"] = aes_encrypt(original, key, iv)
    versions[f"{label}-Partial"] = encrypt_second_half(original, key, iv)
    return versions

def compute_entropy_versions(versions):
    overall = []
    blocks = []
    for name, data in versions.items():
        overall.append(calculate_entropy(data))
        blocks.append(block_entropy(data))
    return overall, blocks

def save_entropy_report(filename, file_type, versions, overall_entropy):
    df = pd.DataFrame({
        "File Name": [filename]*len(versions),
        "Type": [file_type]*len(versions),
        "Version": list(versions.keys()),
        "Overall Entropy": overall_entropy
    })
    # Save in reports folder with timestamp
    csv_path = os.path.join(REPORTS_DIR, f"{filename}_{file_type}_entropy_report.csv")
    df.to_csv(csv_path, index=False)
    return csv_path, df


st.set_page_config(page_title="Entropy Visualization Dashboard", layout="wide")
st.title("📊 Entropy Visualization Dashboard")

file_type = st.radio("Select file type:", ["Text", "Image"])
uploaded_file = st.file_uploader(f"Upload a {file_type} file", type=["txt","jpg","jpeg","png"])

if uploaded_file is not None:
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_file.getbuffer())
        temp_path = tmp.name

    filename_base = os.path.splitext(uploaded_file.name)[0]

    # Generate all versions
    versions = generate_versions(temp_path, file_type)
    overall_entropy, blocks = compute_entropy_versions(versions)

    # Save CSV report in reports folder
    csv_path, df_report = save_entropy_report(filename_base, file_type, versions, overall_entropy)

    st.success(f"✅ Entropy report saved in: `{csv_path}`")

    # CSV download button
    csv_buffer = io.StringIO()
    df_report.to_csv(csv_buffer, index=False)
    st.download_button(
        label="📥 Download CSV Report",
        data=csv_buffer.getvalue().encode(),
        file_name=os.path.basename(csv_path),
        mime="text/csv"
    )


    if file_type == "Text":
        labels = [v for v in versions.keys()]
        fig, ax = plt.subplots(figsize=(8,5))
        ax.bar(labels, overall_entropy)
        ax.axhline(THRESHOLD, linestyle="--", color='red', label="Threshold")
        ax.set_ylabel("Entropy")
        ax.set_title("Text File Entropy Comparison")
        ax.legend()
        plt.xticks(rotation=45)
        st.pyplot(fig)

    elif file_type == "Image":
        # Sort by entropy descending
        sorted_idx = np.argsort(overall_entropy)[::-1]
        sorted_names = [list(versions.keys())[i] for i in sorted_idx]
        sorted_blocks = [blocks[i] for i in sorted_idx]
        sorted_entropy = [overall_entropy[i] for i in sorted_idx]
        labels = sorted_names

        max_len = max(len(b) for b in sorted_blocks)
        padded = [b + [np.nan]*(max_len-len(b)) for b in sorted_blocks]

        fig, ax = plt.subplots(figsize=(10,5))
        im = ax.imshow(padded, aspect='auto', interpolation='nearest', cmap='viridis')
        fig.colorbar(im, ax=ax, label="Entropy")
        ax.set_yticks(range(len(labels)))
        ax.set_yticklabels(labels)
        ax.set_xlabel("Block Number")
        ax.set_title("Image Block-wise Entropy Heatmap (Sorted by Overall Entropy)")
        st.pyplot(fig)

    # Save chart to buffer and provide download
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight')
    buf.seek(0)
    st.download_button(
        label="📥 Download Chart as PNG",
        data=buf,
        file_name=f"{filename_base}_{file_type}_entropy_chart.png",
        mime="image/png"
    )
