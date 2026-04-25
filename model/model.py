import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os

# ── Paths ─────────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "..", "dataset.csv")

# ── Load dataset ──────────────────────────────────────────────────────
print("Loading dataset...")
data = pd.read_csv(DATA_PATH)
print(f"  Total samples: {len(data)}")
print(f"  Phishing: {data['label'].sum()} | Safe: {(data['label']==0).sum()}")

X = data["url"]
y = data["label"]

# ── Train/test split ──────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ── Vectorize ─────────────────────────────────────────────────────────
print("Vectorizing URLs...")
vectorizer = TfidfVectorizer(
    analyzer="char_wb",   # character n-grams — better for URLs
    ngram_range=(2, 4),
    max_features=10000
)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec  = vectorizer.transform(X_test)

# ── Train model ───────────────────────────────────────────────────────
print("Training model...")
model = LogisticRegression(max_iter=1000, C=1.0)
model.fit(X_train_vec, y_train)

# ── Evaluate ──────────────────────────────────────────────────────────
y_pred = model.predict(X_test_vec)
acc = accuracy_score(y_test, y_pred)
print(f"\n✅ Accuracy: {acc*100:.1f}%")
print(classification_report(y_test, y_pred, target_names=["Safe","Phishing"]))

# ── Save model + vectorizer to model/ folder ──────────────────────────
out_dir = BASE_DIR  # saves inside model/ folder
pickle.dump(model,      open(os.path.join(out_dir, "model.pkl"),      "wb"))
pickle.dump(vectorizer, open(os.path.join(out_dir, "vectorizer.pkl"), "wb"))
print("✅ Saved model.pkl and vectorizer.pkl in model/ folder")
