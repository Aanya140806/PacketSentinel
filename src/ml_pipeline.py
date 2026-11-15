import os
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

def demo_dataframe(n=300, seed=7):
    rng=np.random.default_rng(seed)
    labels=np.array(["BENIGN"]*(n//2)+["MALICIOUS"]*(n-n//2)); rng.shuffle(labels)
    mal=labels=="MALICIOUS"
    return pd.DataFrame({"Flow_Duration":rng.normal(1000+mal*1200,350,n).clip(1),
      "Total_Fwd_Packets":rng.poisson(8+mal*15,n),"Total_Bwd_Packets":rng.poisson(7+mal*2,n),
      "Flow_Bytes_s":rng.normal(500+mal*2500,200,n).clip(0),"SYN_Flag_Count":rng.binomial(1,.1+mal*.55,n),"Label":labels})

def prepare(df,label_col):
    df=df.copy(); df.columns=[str(c).strip().replace("\ufeff","") for c in df.columns]
    df=df.loc[:,~df.columns.duplicated()]
    if label_col not in df: raise ValueError(f"Label column '{label_col}' not found.")
    y=df[label_col].astype(str).str.strip()
    X=df.drop(columns=[label_col])
    # Remove likely identifiers/other target aliases to reduce leakage.
    drop=[c for c in X.columns if c.lower().replace("_","").replace(" ","") in
          ["flowid","srcip","sourceip","dstip","destinationip","timestamp","time","label","class","attack","target"]]
    X=X.drop(columns=drop,errors="ignore").apply(pd.to_numeric,errors="coerce")
    X=X.replace([np.inf,-np.inf],np.nan).dropna(axis=1,how="all")
    valid=y.notna() & y.ne("")
    return X.loc[valid].reset_index(drop=True),y.loc[valid].reset_index(drop=True)

def train_model(df,label_col):
    X,y=prepare(df,label_col)
    if len(X)<8 or y.nunique()<2: raise ValueError("Need at least 8 rows and 2 label classes.")
    strat=y if y.value_counts().min()>=2 else None
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.25,random_state=42,stratify=strat)
    model=Pipeline([("imputer",SimpleImputer(strategy="median")),("rf",RandomForestClassifier(n_estimators=150,class_weight="balanced",random_state=42,n_jobs=-1))])
    model.fit(Xtr,ytr); pred=model.predict(Xte); labels=sorted(y.unique())
    metrics={"accuracy":accuracy_score(yte,pred),"precision":precision_score(yte,pred,average="macro",zero_division=0),
      "recall":recall_score(yte,pred,average="macro",zero_division=0),"f1":f1_score(yte,pred,average="macro",zero_division=0),
      "matrix":confusion_matrix(yte,pred,labels=labels).tolist(),"labels":labels,
      "report":classification_report(yte,pred,zero_division=0)}
    importance=sorted(zip(X.columns,model.named_steps["rf"].feature_importances_),key=lambda x:x[1],reverse=True)
    return model,metrics,list(X.columns),importance

def save_model(model,features,path="models/packetsentinel.joblib"):
    os.makedirs(os.path.dirname(path),exist_ok=True); joblib.dump({"model":model,"features":features},path)
def load_model(path="models/packetsentinel.joblib"):
    b=joblib.load(path); return b["model"],b["features"]
def predict_df(model,features,df):
    data=df.copy(); data.columns=[str(c).strip() for c in data.columns]
    data=data.drop(columns=[c for c in data.columns if c.lower().strip() in ["label","class","attack","target"]],errors="ignore")
    X=data.reindex(columns=features).apply(pd.to_numeric,errors="coerce").replace([np.inf,-np.inf],np.nan)
    out=data.copy(); out["PacketSentinel_Prediction"]=model.predict(X)
    if hasattr(model,"predict_proba"): out["Prediction_Confidence"]=model.predict_proba(X).max(axis=1)
    return out
