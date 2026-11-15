# 🛡️ PacketSentinel
## AI-Based Malicious Packet Classification System

PacketSentinel is an academic Computer Networks mini-project demonstrating supervised machine learning on **labeled network-flow CSV data**. It provides a Streamlit dashboard to train a classifier, review evaluation metrics, and predict labels for another CSV.

> **Important:** PacketSentinel is an educational prototype. It does not capture, block, or stop network traffic. A prediction is not proof that a flow is malicious.

## Features
- Train **Random Forest, Extra Trees, Decision Tree, or Logistic Regression**.
- Clean numeric flow features and handle missing values with a median imputer.
- Evaluate on a held-out test split using accuracy, macro precision, macro recall, macro F1, confusion matrix, and classification report.
- Display feature importance for tree-based models.
- Upload a separate CSV for predictions and download the results.
- Save the trained model locally as a Joblib file.

## Tech stack
Python · Streamlit · Pandas · NumPy · Scikit-learn · Matplotlib · Seaborn · Joblib · pytest

## Dataset
The app can use labeled CSV data such as **CICIDS2017**:
- Official page: https://www.unb.ca/cic/datasets/ids-2017.html
- The dataset contains labeled benign and attack network flows; its ML CSVs use CICFlowMeter flow features.
- Keep downloaded dataset files on your computer in a local `data/` directory. **Do not upload the dataset or trained model to GitHub.**

### Dataset citation
Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. 4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal.

## Run on Windows
1. Install Python 3 and VS Code.
2. Download this repository (GitHub **Code → Download ZIP**) and extract it.
3. Open the extracted `PacketSentinel` folder in VS Code.
4. Open **Terminal → New Terminal**, then run:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

5. Open the local URL shown in the terminal (usually http://localhost:8501).

If PowerShell blocks activation, run this once in that terminal:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## How to use
1. Open **Train ML Model**.
2. Choose **Synthetic demo data** first to learn the interface (these are artificial example records, not CICIDS2017).
3. For real dataset analysis, choose **Upload labeled CSV**, select your CSV, and choose its label column (usually `Label`).
4. Select an algorithm and click **Train model**.
5. Review metrics and the confusion matrix. Do not interpret demo-data scores as real cybersecurity performance.
6. Open **Analyze CSV** and upload another CSV with the same feature columns to create downloadable predictions.

## Repository layout
```
PacketSentinel/
├── .github/workflows/python-checks.yml  # Automated Python checks
├── docs/                                # Project documentation
├── src/ml_pipeline.py                   # Preprocessing, training, prediction
├── src/pcap_features.py                 # Experimental basic PCAP flow features
├── src/store.py                          # Local SQLite helper
├── tests/                                # Basic automated checks
├── app.py                                # Streamlit dashboard
├── requirements.txt
└── README.md
```

## Evaluation notes and limitations
- The split is a random held-out split; it is **not** a guarantee of performance on future traffic or unseen attack families.
- Network datasets can be imbalanced, duplicated, or contain identifiers and leakage. This implementation removes common identifier/target-alias columns, but dataset-specific review is still required.
- PCAP feature extraction in `src/pcap_features.py` is experimental and does **not** recreate the complete CICFlowMeter feature schema. Use CICIDS2017's compatible flow CSV for the model demonstrated here.
- Use only datasets/captures you are authorized to analyze.

## Project status
Academic prototype under development. Future work may include a CICFlowMeter-compatible PCAP pipeline, temporal/generalization evaluation, a richer UI, and a separately deployed API.
