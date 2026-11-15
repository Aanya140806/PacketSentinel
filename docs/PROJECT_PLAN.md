# PacketSentinel — Project plan and current implementation

## Aim
Build an educational, offline machine-learning demonstration that classifies labeled network-flow records as benign or malicious.

## Current implemented workflow
1. Load synthetic demo records or a labeled CSV in Streamlit.
2. Select the label/target column.
3. Remove common identifier and target-alias columns.
4. Convert remaining features to numeric values and replace infinite values with missing values.
5. Impute missing feature values using the median.
6. Train one of four classifiers: Random Forest, Extra Trees, Decision Tree, or Logistic Regression.
7. Evaluate on a held-out random test split.
8. Display accuracy, macro precision, macro recall, macro F1, confusion matrix, and classification report.
9. Save the model locally and predict on another CSV with matching feature names.

## Dataset
Recommended dataset: CICIDS2017 (official page: https://www.unb.ca/cic/datasets/ids-2017.html).

Use the dataset's labeled flow CSV files. Keep the dataset locally; do not commit it to GitHub. Cite:
Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*. ICISSP.

## Metrics and interpretation
Accuracy, macro precision, macro recall, macro F1, confusion matrix, and class-wise precision/recall. Explain false positives and false negatives. The current random split does not establish temporal or unseen-attack generalization.

## Safety and limitations
- Offline academic analysis only; no automatic blocking or unauthorized capture.
- Synthetic demo records are artificial and must not be presented as real dataset results.
- Experimental Scapy feature extraction is not compatible with the full CICFlowMeter feature schema. Use compatible CICIDS flow CSVs for the demonstrated model.
- Results depend on dataset quality, feature leakage, class balance, duplicates, and split design.

## Future improvements
- CICFlowMeter-compatible PCAP feature extraction.
- Temporal train/test split and unseen-attack evaluation.
- Dataset-specific preprocessing and feature validation.
- Optional FastAPI service and React frontend.
