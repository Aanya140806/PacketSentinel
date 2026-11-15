# Project plan
**Title:** PacketSentinel — AI-Based Malicious Packet Classification System

## Aim
Classify labeled network-flow records as benign or malicious using supervised machine learning.

## Pipeline
CSV dataset → numeric feature cleaning → train/test split → Random Forest → metrics/confusion matrix → predictions dashboard.

## Dataset
CICIDS2017 official dataset: https://www.unb.ca/cic/datasets/ids-2017.html
Reference paper: Sharafaldin, I., Lashkari, A., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. ICISSP.

## Metrics
Accuracy, macro precision, macro recall, macro F1, confusion matrix. Discuss class imbalance, data leakage, false positives/negatives and generalization.

## Safety and limitations
Offline academic analysis only. No automatic blocking, scanning, or unauthorized capture. This is not a production IDS.
