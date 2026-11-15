# PacketSentinel
AI-Based Malicious Packet Classification System — beginner starter.

## Run on Windows
1. Extract this ZIP.
2. Open the `PacketSentinel` folder in VS Code (File → Open Folder).
3. Terminal → New Terminal.
4. Run each command separately:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```
If activation is blocked, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again.
5. Open `http://localhost:8501` in your browser.
6. Select **Train ML Model**, use demo data, and click **Train model**.

Dataset recommendation: CICIDS2017 https://www.unb.ca/cic/datasets/ids-2017.html
This is an academic prototype, not a production IDS. Analyze only data you are authorized to use.
