PacketSentinel
AI-Based Malicious Packet Classification System
PacketSentinel is a beginner-friendly Computer Networks mini-project that demonstrates how machine learning can classify network-flow records as BENIGN or MALICIOUS. It provides a Streamlit dashboard for model training, evaluation, CSV analysis, and viewing prediction results.
> **Project status:** Academic prototype / starter implementation. Results depend on the dataset and selected features; this project is not a production intrusion-detection or firewall system.
Project objectives
Explore how machine learning can support network traffic classification.
Train and compare common classification algorithms on labeled network-flow data.
Display evaluation metrics and a confusion matrix in an interactive dashboard.
Allow a user to upload a CSV and inspect predicted labels.
Keep a simple local history of predictions.
Features
Train Random Forest, Decision Tree, or Logistic Regression models.
Show accuracy, precision, recall, F1-score, confusion matrix, and classification report.
Display feature importance when supported by the selected model.
Upload a CSV for classification and download the results.
Store prediction history locally using SQLite.
Technology stack
Area	Technology
Language	Python
Dashboard	Streamlit
Data handling	Pandas, NumPy
Machine learning	Scikit-learn
Charts	Matplotlib, Seaborn
Model persistence	Joblib
Packet processing (optional)	Scapy
Local history	SQLite
System workflow
```text
Labeled network-flow CSV
        ↓
Data selection and preprocessing
        ↓
Train / evaluate ML classifier
        ↓
Metrics + confusion matrix + feature importance
        ↓
Upload another CSV for prediction
        ↓
Predicted labels + downloadable results + local history
```
Dataset
The project is designed to work with labeled network-flow CSV data, such as CICIDS2017.
Dataset page: https://www.unb.ca/cic/datasets/ids-2017.html
CICIDS2017 includes labeled benign traffic and multiple attack categories. Its machine-learning CSV files contain flow-based features generated using CICFlowMeter.
Do not upload the dataset files to this repository; keep them locally in a `data/` folder.
Dataset citation
Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. 4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal.
Installation (Windows)
Install Python 3 and VS Code.
Download or clone this repository.
Open the `PacketSentinel` folder in VS Code.
In the VS Code terminal, run:
```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   streamlit run app.py
   ```
Streamlit will display a local URL (usually `http://localhost:8501`). Open it in your browser.
Repository structure
```text
PacketSentinel/
├── docs/              # Project documentation
├── src/               # Supporting Python modules
├── app.py             # Streamlit dashboard
├── requirements.txt    # Python dependencies
├── README.md           # Project overview and instructions
└── .gitignore         # Files excluded from Git
```
Screenshots
Add screenshots of the running dashboard here when available.
Suggested screenshots:
Overview page
Model training and evaluation
CSV analysis / prediction results
Important limitations
This is an educational prototype, not a production security product.
Model performance depends on dataset quality, class balance, preprocessing, and train/test split.
Dataset-specific flow features may not match features extracted from arbitrary PCAP files. PCAP support requires compatible feature extraction.
Predictions are indicators for analysis and should not be treated as definitive proof that traffic is malicious.
Use only datasets and network captures you are authorized to analyze.
Future improvements
Add a FastAPI backend and a separate React frontend.
Add robust preprocessing and dataset-specific feature validation.
Support multiclass attack-family classification.
Add improved PCAP-to-flow feature extraction compatible with the training dataset.
Add model export and clearer prediction-history filters.
License
This repository is intended for academic and educational use. Dataset licensing and citation requirements remain those of the dataset provider.
