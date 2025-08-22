
from flask import Flask, request, jsonify
from flask_cors import CORS
import os, joblib
import pandas as pd
from urllib.parse import urlparse

# --------- Load artifacts (expect files in same folder) ---------
HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "url_phishshield.joblib")
ENCODER_PATH = os.path.join(HERE, "label_encoder.joblib")
FEATS_PATH = os.path.join(HERE, "feature_names.joblib")

# Lazy load so the server can start even if numpy versions differ in some environments.
_model = None
_le = None
_feature_names = None

def load_artifacts():
    global _model, _le, _feature_names
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    if _le is None:
        _le = joblib.load(ENCODER_PATH)
    if _feature_names is None:
        _feature_names = joblib.load(FEATS_PATH)

def extract_features(url: str):
    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse("")
    features = {}
    features['url_length'] = len(url or '')
    features['num_dots'] = (url or '').count('.')
    features['num_hyphens'] = (url or '').count('-')
    features['num_digits'] = sum(c.isdigit() for c in (url or ''))
    features['https'] = 1 if parsed.scheme == "https" else 0
    # subdomains = netloc parts minus root + tld (approx as count('.') - 1)
    netloc = parsed.netloc or ''
    features['num_subdomains'] = max(netloc.count('.') - 1, 0)
    keywords = ['login','secure','account','update','bank','verify','free','paypal']
    low = (url or '').lower()
    features['keywords_count'] = sum(1 for kw in keywords if kw in low)
    return features

def compute_risk_percent(prob_phish: float) -> int:
    # Clamp and convert to 0-100 integer
    p = max(0.0, min(1.0, float(prob_phish)))
    return int(round(p * 100))

app = Flask(__name__)
CORS(app)

@app.get("/health")
def health():
    ok = all(os.path.exists(p) for p in [MODEL_PATH, ENCODER_PATH, FEATS_PATH])
    return jsonify(status="ok" if ok else "missing_artifacts",
                   model=os.path.basename(MODEL_PATH),
                   encoder=os.path.basename(ENCODER_PATH),
                   features=os.path.basename(FEATS_PATH))

@app.post("/predict")
def predict():
    # Expect JSON: {"url": "https://example.com"}
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not url:
        return jsonify(error="url is required"), 400

    # Load artifacts
    load_artifacts()

    # Build dataframe with correct feature order
    feats = extract_features(url)
    try:
        X = pd.DataFrame([feats])[_feature_names]
    except KeyError:
        # In case feature set changed, align by available columns and fill missing with 0.
        X = pd.DataFrame([feats])
        for col in _feature_names:
            if col not in X.columns:
                X[col] = 0
        X = X[_feature_names]

    # Predict probabilities
    if hasattr(_model, "predict_proba"):
        proba = _model.predict_proba(X)[0]
    else:
        # Fallback: use decision_function or hard prediction
        try:
            decision = _model.decision_function(X)
            # map to pseudo-probabilities via logistic
            import math
            p1 = 1.0 / (1.0 + math.exp(-float(decision)))
            proba = [1 - p1, p1]
        except Exception:
            pred = int(_model.predict(X)[0])
            proba = [1.0, 0.0] if pred == 0 else [0.0, 1.0]

    classes = list(getattr(_le, "classes_", [])) or list(getattr(_model, "classes_", []))
    # Determine which index corresponds to "phishing"
    phishing_aliases = {"phishing","phish","malicious","fraud","spam","bad"}
    phish_index = None
    for i, c in enumerate(classes):
        if str(c).strip().lower() in phishing_aliases:
            phish_index = i
            break
    if phish_index is None:
        # Heuristic: if two classes, assume the lexicographically larger name is 'phishing' often,
        # but also look for 'legit' keywords.
        legit_aliases = {"legit","legitimate","benign","safe","good","clean"}
        if len(classes) == 2:
            # Pick the non-legit as phishing
            if str(classes[0]).strip().lower() in legit_aliases:
                phish_index = 1
            elif str(classes[1]).strip().lower() in legit_aliases:
                phish_index = 0
        # Fallback to the last class index
        if phish_index is None:
            phish_index = (len(classes) - 1) if len(classes) else 1

    prob_phish = float(proba[phish_index]) if phish_index < len(proba) else float(proba[-1])
    risk_percent = compute_risk_percent(prob_phish)
    label_pred = str(_le.inverse_transform([int(_model.predict(X)[0])])[0]) if hasattr(_le, "inverse_transform") else str(_model.predict(X)[0])

    return jsonify(
        url=url,
        classes=classes,
        prob_phish=prob_phish,
        risk_percent=risk_percent,
        label_pred=label_pred,
        features=feats
    )

# if __name__ == "__main__":
#     # Run on localhost:5000
#     app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    # Run on all devices in the local network
    app.run(host="0.0.0.0", port=5000, debug=False)