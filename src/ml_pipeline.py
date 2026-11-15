"""Training and prediction helpers for PacketSentinel (offline academic prototype)."""
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             confusion_matrix, classification_report)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier

IDENTIFIER_COLUMNS = {
    "flowid", "srcip", "sourceip", "dstip", "destinationip", "timestamp",
    "time", "sourceport", "destinationport", "srcport", "dstport"
}
TARGET_ALIASES = {"label", "class", "attack", "target", "category"}

def demo_dataframe(n=400, seed=7):
    """Create clearly synthetic data for learning the app—not real network evidence."""
    rng = np.random.default_rng(seed)
    labels = np.array(["BENIGN"] * (n // 2) + ["MALICIOUS"] * (n - n // 2))
    rng.shuffle(labels)
    malicious = labels == "MALICIOUS"
    return pd.DataFrame({
        "Flow_Duration": rng.normal(1000 + malicious * 1200, 350, n).clip(1),
        "Total_Fwd_Packets": rng.poisson(8 + malicious * 15, n),
        "Total_Bwd_Packets": rng.poisson(7 + malicious * 2, n),
        "Flow_Bytes_s": rng.normal(500 + malicious * 2500, 200, n).clip(0),
        "SYN_Flag_Count": rng.binomial(1, .1 + malicious * .55, n),
        "Label": labels,
    })

def prepare(df, label_col):
    """Clean headers, remove likely identifiers/target aliases, and numericize features."""
    if label_col not in df.columns:
        raise ValueError(f"Label column '{label_col}' not found.")
    data = df.copy()
    data.columns = [str(c).strip().replace("\ufeff", "") for c in data.columns]
    data = data.loc[:, ~data.columns.duplicated()]
    label_col = next((c for c in data.columns if c == label_col), None)
    if label_col is None:
        raise ValueError("Selected label column disappeared after cleaning headers.")
    y = data[label_col].astype("string").str.strip()
    X = data.drop(columns=[label_col])
    # Avoid obvious identifiers and duplicate target columns causing leakage.
    drop = [c for c in X.columns if c.lower().replace("_", "").replace(" ", "") in
            IDENTIFIER_COLUMNS or c.lower().strip() in TARGET_ALIASES]
    X = X.drop(columns=drop, errors="ignore")
    X = X.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    X = X.dropna(axis=1, how="all")
    valid = y.notna() & y.ne("")
    X, y = X.loc[valid].reset_index(drop=True), y.loc[valid].reset_index(drop=True)
    if X.shape[1] == 0:
        raise ValueError("No usable numeric feature columns found. Check your CSV.")
    return X, y

def make_estimator(algorithm):
    if algorithm == "Random Forest":
        return RandomForestClassifier(n_estimators=160, class_weight="balanced",
                                     random_state=42, n_jobs=-1)
    if algorithm == "Extra Trees":
        return ExtraTreesClassifier(n_estimators=160, class_weight="balanced",
                                    random_state=42, n_jobs=-1)
    if algorithm == "Decision Tree":
        return DecisionTreeClassifier(class_weight="balanced", random_state=42)
    if algorithm == "Logistic Regression":
        return LogisticRegression(max_iter=1200, class_weight="balanced")
    raise ValueError("Unknown algorithm selected.")

def train_model(df, label_col, algorithm="Random Forest", test_size=0.25):
    X, y = prepare(df, label_col)
    counts = y.value_counts()
    if len(X) < 12 or y.nunique() < 2:
        raise ValueError("Need at least 12 usable rows and at least 2 label classes.")
    stratify = y if counts.min() >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=stratify)
    model = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", make_estimator(algorithm)),
    ])
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    labels = sorted(y.unique().tolist())
    matrix = confusion_matrix(y_test, pred, labels=labels)
    metrics = {
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(precision_score(y_test, pred, average="macro", zero_division=0)),
        "recall": float(recall_score(y_test, pred, average="macro", zero_division=0)),
        "f1": float(f1_score(y_test, pred, average="macro", zero_division=0)),
        "matrix": matrix.tolist(),
        "labels": labels,
        "report": classification_report(y_test, pred, zero_division=0),
        "test_rows": int(len(y_test)),
        "train_rows": int(len(y_train)),
    }
    classifier = model.named_steps["classifier"]
    if hasattr(classifier, "feature_importances_"):
        importances = classifier.feature_importances_
        importance = sorted(zip(X.columns.tolist(), importances.tolist()),
                           key=lambda item: item[1], reverse=True)
    else:
        importance = []
    bundle = {"model": model, "features": X.columns.tolist(),
              "algorithm": algorithm, "classes": labels}
    return bundle, metrics, importance

def save_model(bundle, path="models/packetsentinel.joblib"):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)

def load_model(path="models/packetsentinel.joblib"):
    return joblib.load(path)

def predict_df(bundle, df):
    """Predict from a CSV with matching numeric feature names."""
    raw = df.copy()
    raw.columns = [str(c).strip().replace("\ufeff", "") for c in raw.columns]
    raw = raw.loc[:, ~raw.columns.duplicated()]
    # Do not accidentally use a label column as an input feature.
    raw = raw.drop(columns=[c for c in raw.columns if c.lower().strip() in TARGET_ALIASES],
                   errors="ignore")
    X = raw.reindex(columns=bundle["features"]).apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    result = raw.copy()
    result["PacketSentinel_Prediction"] = bundle["model"].predict(X)
    if hasattr(bundle["model"], "predict_proba"):
        result["Prediction_Confidence"] = bundle["model"].predict_proba(X).max(axis=1)
    return result
