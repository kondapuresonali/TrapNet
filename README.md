# 🕸 TrapNet — Cyber Intelligence System

> A real-time phishing & malicious URL detection system powered by Machine Learning, VirusTotal API, WHOIS intelligence, and AI-generated threat analysis.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.1-black?style=flat-square&logo=flask)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API-blue?style=flat-square)
![ML](https://img.shields.io/badge/ML-Scikit--Learn-orange?style=flat-square&logo=scikit-learn)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## 📸 Demo

| Scan Result | History & Charts |
|---|---|
| ![scan](https://via.placeholder.com/400x250/0e1122/a78bfa?text=Phishing+Detected) | ![history](https://via.placeholder.com/400x250/0e1122/00e096?text=Threat+Distribution) |

> Replace the above placeholders with actual screenshots from your running app.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **URL Scanner** | Analyzes any URL using 9+ rule-based heuristics |
| 🛡 **VirusTotal Integration** | Queries 90+ security vendors in real-time |
| 🤖 **ML Model** | TF-IDF + Logistic Regression trained on phishing dataset |
| 🧠 **AI Explanation** | Claude API generates plain-English threat summaries |
| 📅 **WHOIS Domain Age** | Flags domains less than 30 days old via RDAP |
| 🔒 **SSL Certificate Check** | Validates HTTPS and certificate details |
| 🌐 **IP Geolocation** | Resolves IP and checks for suspicious hosting |
| 🎯 **Typosquatting Detector** | Detects brand impersonation (paypa1, g00gle, etc.) |
| 📋 **Bulk URL Scanner** | Scan up to 20 URLs at once with summary stats |
| 📊 **Scan History + Charts** | Chart.js doughnut chart showing threat distribution |
| ⬇ **PDF Export** | Download full threat report as a branded PDF |
| 🕐 **Animated Loading** | 7-step scan progress animation |

---

## 🗂 Project Structure

```
TrapNet/
├── app.py                    # Main Flask application
├── dataset.csv               # Phishing URL training dataset
├── requirements.txt          # Python dependencies
├── trapnet.db                # SQLite scan history (auto-created)
│
├── model/
│   ├── model.py              # ML training script
│   ├── model.pkl             # Trained model (generated)
│   └── vectorizer.pkl        # TF-IDF vectorizer (generated)
│
├── services/
│   ├── virustotal_service.py # VirusTotal API integration
│   ├── WHOIS.py              # WHOIS / RDAP domain age checker
│   ├── ssl_service.py        # SSL certificate validator
│   └── ip_service.py        # IP geolocation service
│
├── static/
│   └── style.css             # Dark cyber UI styles
│
└── templates/
    └── index.html            # Main frontend (HTML + JS)
```

---

## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/trapnet.git
cd trapnet
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Train the ML model
```bash
python model/model.py
```
This generates `model/model.pkl` and `model/vectorizer.pkl`.

### 4. Set your API keys

**Option A — Environment variables (recommended):**
```bash
# Windows (PowerShell)
$env:VT_API_KEY = "your_virustotal_key_here"
$env:ANTHROPIC_API_KEY = "your_anthropic_key_here"

# Mac / Linux
export VT_API_KEY="your_virustotal_key_here"
export ANTHROPIC_API_KEY="your_anthropic_key_here"
```

**Option B — Edit directly in `app.py`:**
```python
VT_API_KEY    = "your_virustotal_key_here"
ANTHROPIC_KEY = "your_anthropic_key_here"
```

### 5. Run the app
```bash
python app.py
```
Open [http://localhost:5000](http://localhost:5000)

---

## 🔑 Getting Free API Keys

### VirusTotal (for 90+ vendor scanning)
1. Go to [virustotal.com](https://www.virustotal.com) → Sign up free
2. Click your avatar → **API Key** → Copy
3. Free tier: 4 requests/minute, 500/day

### Anthropic Claude (for AI threat explanation)
1. Go to [console.anthropic.com](https://console.anthropic.com) → Sign up
2. Go to **API Keys** → Create Key → Copy
3. Free $5 credits on signup (~500 AI explanations)

---

## 🧠 How the Threat Score Works

TrapNet calculates a **0–100 risk score** by combining multiple signals:

```
Rule-based checks     → up to 40 pts
  • No HTTPS          → +20
  • Raw IP address    → +20
  • @ in URL          → +20
  • Suspicious TLD    → +15
  • Brand keywords    → +8 each
  • Brand impersonation → +30
  • New domain (<30d) → +20
  • Typosquatting     → +25

ML Model (TF-IDF)     → up to 40 pts
VirusTotal vendors    → up to 30 pts
──────────────────────────────────────
Final score capped at 100
```

| Score | Threat Level |
|---|---|
| 0–14 | ✅ Safe |
| 15–39 | 🟡 Low |
| 40–69 | 🟠 Suspicious |
| 70–100 | 🔴 High / Phishing |

---

## 🚀 Deployment

### Deploy on Render (free)
1. Push code to GitHub
2. Go to [render.com](https://render.com) → New Web Service
3. Connect your GitHub repo
4. Build command: `pip install -r requirements.txt`
5. Start command: `python app.py`
6. Add environment variables: `VT_API_KEY`, `ANTHROPIC_API_KEY`

### Deploy frontend on Netlify (if separated)
1. Go to [netlify.com](https://netlify.com) → New site from Git
2. Connect repo → Deploy

---

## 📦 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask 3.1 |
| ML | Scikit-learn, TF-IDF, Logistic Regression |
| Threat Intel | VirusTotal API v3, RDAP/WHOIS |
| AI | Anthropic Claude Haiku API |
| Frontend | HTML5, CSS3, Vanilla JS, Chart.js |
| PDF Export | ReportLab |
| Database | SQLite (scan history) |
| Deployment | Render (backend), Netlify (frontend) |

---

## 🔮 Roadmap

- [ ] Chrome Extension for real-time link scanning
- [ ] Email phishing header analyzer
- [ ] Dark/Light mode toggle
- [ ] User accounts with personal scan history
- [ ] Webhook alerts for high-risk scans
- [ ] REST API for third-party integrations

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first.

1. Fork the repo
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 👨‍💻 Author

Built with 🔥 by **SONALI**

[![GitHub](https://img.shields.io/badge/GitHub-@kondapuresonali-black?style=flat-square&logo=github)](https://github.com/kondapuresonali)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat-square&logo=linkedin)](https://linkedin.com/in/yourusername)

---

> ⭐ Star this repo if TrapNet helped you learn something new!
