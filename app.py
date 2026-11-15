import os
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from src.ml_pipeline import demo_dataframe, train_model, save_model, load_model, predict_df

st.set_page_config(page_title="PacketSentinel", page_icon="🛡️", layout="wide")
st.title("🛡️ PacketSentinel")
st.caption("AI-Based Malicious Packet Classification System | Academic prototype")
st.warning("Educational/offline analysis only. Predictions are not proof of malicious activity and this app does not block traffic.")

MODEL_PATH = "models/packetsentinel.joblib"
if "bundle" not in st.session_state:
    st.session_state.bundle = None
if "metrics" not in st.session_state:
    st.session_state.metrics = None
if "importance" not in st.session_state:
    st.session_state.importance = []

page = st.sidebar.radio("Navigate", ["Overview", "Train ML Model", "Analyze CSV"])

if page == "Overview":
    st.subheader("What does PacketSentinel do?")
    st.write("It learns patterns from labeled network-flow CSV records and predicts a label for new records.")
    st.markdown("**Workflow:** CSV → preprocessing → model training → evaluation → predictions")
    a, b, c = st.columns(3)
    a.metric("Learning models", "4")
    b.metric("Input", "Flow CSV")
    c.metric("Mode", "Offline")
    st.info("Start with the synthetic demo to understand the app. It is artificial practice data, not real network traffic.")
    st.markdown("### Getting started")
    st.markdown("1. Open **Train ML Model**.\n2. Choose synthetic demo or upload a labeled CSV.\n3. Select the column containing the labels.\n4. Train and review the metrics.\n5. Open **Analyze CSV** to predict labels for a separate CSV with matching features.")
    st.markdown("### Dataset")
    st.markdown("[CICIDS2017 official dataset page](https://www.unb.ca/cic/datasets/ids-2017.html)")

elif page == "Train ML Model":
    source = st.radio("Data source", ["Synthetic demo data", "Upload labeled CSV"], horizontal=True)
    df = None
    if source == "Synthetic demo data":
        df = demo_dataframe()
        st.caption("Synthetic data is only for learning the interface. Do not report its scores as real cybersecurity results.")
        st.dataframe(df.head(), use_container_width=True)
    else:
        up = st.file_uploader("Upload a labeled CSV", type=["csv"], key="training_csv")
        if up:
            try:
                df = pd.read_csv(up, low_memory=False)
                st.success(f"Loaded {len(df):,} rows and {len(df.columns)} columns.")
                st.dataframe(df.head(), use_container_width=True)
            except Exception as exc:
                st.error(f"Could not read CSV: {exc}")

    if df is not None:
        label_options = list(df.columns)
        default_index = label_options.index("Label") if "Label" in label_options else len(label_options) - 1
        label = st.selectbox("Which column contains the correct labels?", label_options, index=default_index)
        algorithm = st.selectbox("Choose model", ["Random Forest", "Extra Trees", "Decision Tree", "Logistic Regression"])
        if st.button("Train model", type="primary"):
            try:
                with st.spinner("Training and evaluating..."):
                    bundle, metrics, importance = train_model(df, label, algorithm)
                    save_model(bundle, MODEL_PATH)
                st.session_state.bundle = bundle
                st.session_state.metrics = metrics
                st.session_state.importance = importance
                st.success("Training complete. Model saved locally in models/packetsentinel.joblib")
            except Exception as exc:
                st.error(f"Training failed: {exc}")

    if st.session_state.metrics:
        m = st.session_state.metrics
        st.subheader("Evaluation (held-out test split)")
        cols = st.columns(4)
        cols[0].metric("Accuracy", f"{m['accuracy']:.1%}")
        cols[1].metric("Macro precision", f"{m['precision']:.1%}")
        cols[2].metric("Macro recall", f"{m['recall']:.1%}")
        cols[3].metric("Macro F1", f"{m['f1']:.1%}")
        st.caption(f"Training rows: {m['train_rows']:,} | Test rows: {m['test_rows']:,}")
        fig, ax = plt.subplots()
        sns.heatmap(m["matrix"], annot=True, fmt="d", cmap="Blues",
                    xticklabels=m["labels"], yticklabels=m["labels"], ax=ax)
        ax.set_xlabel("Predicted label")
        ax.set_ylabel("Actual label")
        st.pyplot(fig)
        plt.close(fig)
        st.subheader("Classification report")
        st.code(m["report"])
        if st.session_state.importance:
            st.subheader("Feature importance")
            imp = pd.DataFrame(st.session_state.importance, columns=["Feature", "Importance"]).head(15)
            st.bar_chart(imp.set_index("Feature"))
        with open(MODEL_PATH, "rb") as model_file:
            st.download_button("Download trained model (.joblib)", model_file,
                               file_name="packetsentinel.joblib")

else:
    if st.session_state.bundle is None and os.path.exists(MODEL_PATH):
        if st.button("Load saved model"):
            try:
                st.session_state.bundle = load_model(MODEL_PATH)
                st.success("Saved model loaded.")
            except Exception as exc:
                st.error(f"Could not load model: {exc}")
    if st.session_state.bundle is None:
        st.info("Train a model first, or click **Load saved model** if you trained it in an earlier session.")
    else:
        up = st.file_uploader("Upload a CSV with matching numeric feature columns", type=["csv"], key="prediction_csv")
        if up:
            try:
                raw = pd.read_csv(up, low_memory=False)
                result = predict_df(st.session_state.bundle, raw)
                st.success(f"Predictions created for {len(result):,} rows.")
                st.dataframe(result.head(100), use_container_width=True)
                st.download_button("Download all predictions (CSV)",
                                  result.to_csv(index=False).encode("utf-8"),
                                  file_name="packetsentinel_predictions.csv",
                                  mime="text/csv")
            except Exception as exc:
                st.error(f"Prediction failed: {exc}")
