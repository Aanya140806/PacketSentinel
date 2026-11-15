import os, streamlit as st, pandas as pd, matplotlib.pyplot as plt, seaborn as sns
from src.ml_pipeline import demo_dataframe,train_model,save_model,load_model,predict_df
st.set_page_config(page_title="PacketSentinel",page_icon="🛡️",layout="wide")
st.title("🛡️ PacketSentinel")
st.caption("AI-Based Malicious Packet Classification System | Student prototype")
page=st.sidebar.radio("Navigate",["Overview","Train ML Model","Analyze CSV"])
if "model" not in st.session_state: st.session_state.model=None
if "features" not in st.session_state: st.session_state.features=None
if "metrics" not in st.session_state: st.session_state.metrics=None
if page=="Overview":
 st.metric("Classifier","Random Forest")
 st.markdown("**Workflow:** labeled CSV → cleaning → ML training → evaluation → prediction on new CSV.")
 st.info("Begin with synthetic demo data. It is only for practicing the app, not real network traffic.")
 st.warning("Academic prototype only; it does not block packets or replace a real security system.")
elif page=="Train ML Model":
 source=st.radio("Data source",["Synthetic demo data","Upload labeled CSV"],horizontal=True)
 df=demo_dataframe() if source=="Synthetic demo data" else None
 if source=="Synthetic demo data": st.dataframe(df.head(),use_container_width=True)
 else:
  up=st.file_uploader("Upload labeled CSV",type="csv")
  if up:
   try: df=pd.read_csv(up,low_memory=False); st.write(f"{len(df):,} rows • {len(df.columns)} columns"); st.dataframe(df.head(),use_container_width=True)
   except Exception as e: st.error(str(e))
 if df is not None:
  label=st.selectbox("Label column",df.columns,index=list(df.columns).index("Label") if "Label" in df.columns else len(df.columns)-1)
  if st.button("🚀 Train model",type="primary"):
   try:
    with st.spinner("Training..."): model,m,features,imp=train_model(df,label); save_model(model,features)
    st.session_state.model=model; st.session_state.features=features; st.session_state.metrics=m; st.session_state.importance=imp; st.success("Model trained and saved!")
   except Exception as e: st.error(f"Training error: {e}")
 if st.session_state.metrics:
  m=st.session_state.metrics; a,b,c,d=st.columns(4)
  a.metric("Accuracy",f"{m['accuracy']:.1%}"); b.metric("Precision",f"{m['precision']:.1%}"); c.metric("Recall",f"{m['recall']:.1%}"); d.metric("F1",f"{m['f1']:.1%}")
  fig,ax=plt.subplots(); sns.heatmap(m["matrix"],annot=True,fmt="d",cmap="Blues",xticklabels=m["labels"],yticklabels=m["labels"],ax=ax); ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); st.pyplot(fig)
  st.subheader("Classification report"); st.code(m["report"])
  st.subheader("Feature importance"); st.dataframe(pd.DataFrame(st.session_state.importance,columns=["Feature","Importance"]).head(15))
elif page=="Analyze CSV":
 if st.session_state.model is None and os.path.exists("models/packetsentinel.joblib") and st.button("Load saved model"):
  st.session_state.model,st.session_state.features=load_model(); st.success("Model loaded.")
 if st.session_state.model is None: st.info("Train a model first.")
 else:
  up=st.file_uploader("Upload CSV with matching feature columns",type="csv")
  if up:
   try:
    raw=pd.read_csv(up,low_memory=False); result=predict_df(st.session_state.model,st.session_state.features,raw)
    st.dataframe(result,use_container_width=True); st.download_button("Download predictions",result.to_csv(index=False).encode(),file_name="packetsentinel_predictions.csv")
   except Exception as e: st.error(f"Prediction failed: {e}")
