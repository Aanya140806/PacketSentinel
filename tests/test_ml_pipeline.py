import pandas as pd
from src.ml_pipeline import demo_dataframe, prepare, train_model, predict_df

def test_demo_data_has_two_classes():
    df = demo_dataframe(40)
    assert set(df["Label"]) == {"BENIGN", "MALICIOUS"}

def test_prepare_removes_label_and_identifier():
    df = demo_dataframe(30)
    df["FlowID"] = "example"
    X, y = prepare(df, "Label")
    assert "Label" not in X.columns
    assert "FlowID" not in X.columns
    assert len(X) == len(y)

def test_train_and_predict_smoke():
    df = demo_dataframe(80)
    bundle, metrics, importance = train_model(df, "Label")
    assert 0 <= metrics["accuracy"] <= 1
    predicted = predict_df(bundle, df.drop(columns=["Label"]).head(5))
    assert len(predicted) == 5
    assert "PacketSentinel_Prediction" in predicted.columns
