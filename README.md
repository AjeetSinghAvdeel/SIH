# SIH Project

A full-stack application built with **FastAPI** (backend) and **React/Next.js** (frontend).  
It provides system utilities such as device scanning, secure wiping, and certificate management, all with a modern UI.

---

## 🚀 Features
- 🔍 **Device Scanner** – Detect and analyze connected devices.  
- 🧹 **Secure Wipe** – Safely erase files and free disk space.  
- 📜 **Certificate Manager** – Generate, view, and download certificates.  
- ⚙️ **System Utilities** – CPU, memory, and platform insights.  
- 🎨 **Modern UI** – Built with TailwindCSS, shadcn/ui, and Lovable.ai starter.  

---

## 📂 Project Structure
```
SIH/
│
├── backend/                           # FastAPI Backend
│   ├── server.py                      # Main FastAPI app (APIs for wipe, certs, tamper detection)
│   ├── requirements.txt               # Backend dependencies
│   ├── certificates/                  # Folder for generated certificates
│   ├── data/                          # Local data storage
│   │   ├── certificates.json          # Stores certificate metadata
│   │   └── registered_files.json      # Stores tamper-detection file hashes
│   ├── utils/                         # Helper scripts
│   │   ├── wipe_methods.py            # Secure wipe logic
│   │   ├── certificate_generator.py   # PDF generation
│   │   └── tamper_utils.py            # Hashing & verification
│   └── __init__.py
│
├── frontend/                          # React (Next.js or Vite) Frontend
│   ├── package.json
│   ├── tsconfig.json
│   ├── public/                        # Static assets
│   │   └── favicon.ico
│   ├── src/
│   │   ├── App.tsx / index.tsx        # App entry
│   │   ├── components/                # UI Components
│   │   │   ├── certificates/CertificateManager.tsx                  
│   │   │   ├── charts/RiskGauge.tsx
│   │   │   ├── compliance/ComplianceDashboard.tsx
│   │   │   ├── scanning/DeviceScanner.tsx 
│   │   │   ├── settings/SettingsTab.tsx
│   │   │   ├── ui/                    # shadcn/ui components
│   │   │   ├── verification/TamperDetection.tsx
│   │   │   ├── wiping/SecureWipe.tsx
│   │   │   ├── settings/SettingsTab.tsx
│   │   │   ├── CertificatesList.jsx
│   │   │   └── ProtectedRoute.tsx
│   │   ├── pages/                     # Routes
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Landing.tsx
│   │   │   ├── Login.tsx
│   │   │   ├── Notfound.tsx
│   │   │   └── Register.tsx
│   │   ├── styles/                    # Tailwind / custom styles
│   │   └── firebaseConfig.ts          # Firebase integration
│
├── .gitignore
├── README.md
└── LICENSE (optional)
```

---

## ⚡ Installation & Setup

### Clone the repository
```bash

git clone https://github.com/AjeetSinghAvdeel/SIH.git
cd SIH

cd backend
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload

cd frontend
npm install
npm run dev
```

🛠️ Tech Stack

Backend: FastAPI, Python, Uvicorn

Frontend: React / Next.js, TailwindCSS, shadcn/ui

Other: psutil, subprocess, reportlab (PDF generation)
