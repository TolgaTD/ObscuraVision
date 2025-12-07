# ObscuraVision 🛡️👁️
**Next-Generation AI-Powered Android Malware Analysis System**

ObscuraVision is an advanced academic project designed to modernize mobile application security analysis. It integrates static analysis (**MobSF**), multi-engine scanning (**VirusTotal**), and Generative AI (**Google Gemini / Ollama**) to provide a comprehensive verdict on Android APK files.

![ObscuraVision Interface](static/obscura_vision_hero.png)


## 🚀 Key Features

*   **⚡ Automated Static Analysis:** Leverages [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) to extract permissions, secrets, API calls, and manifest vulnerabilities.
*   **🌍 Multi-Engine Detection:** Queries [VirusTotal API v3](https://www.virustotal.com/) to check file reputation against 70+ antivirus engines.
*   **🧠 AI-Powered Verdicts:** Uses LLMs (Google Gemini 1.5 Flash or Local Ollama models) to synthesize technical data into a human-readable "MALICIOUS", "SUSPICIOUS", or "BENIGN" verdict with reasoning.
*   **🔍 Smart Caching:** Implements SHA-256 hash checks to retrieve existing analysis results instantly, saving API quotas and time.
*   **🎨 Modern UI:** A sleek, dark-themed responsive interface built with HTML5, CSS3, and JavaScript.

## 🛠️ Tech Stack

*   **Backend:** Python 3.10+, FastAPI, Uvicorn, httpx
*   **Frontend:** Vanilla JS, CSS3, HTML5
*   **AI Integration:** Google Gemini API, Ollama (Local LLM)
*   **Security Tools:** MobSF (Mobile Security Framework), VirusTotal

## ⚙️ Installation & Setup

1.  **Prerequisites:**
    *   Python 3.10+
    *   MobSF running locally (default: `http://127.0.0.1:8000`)
    *   VirusTotal API Key

2.  **Clone the Repository:**
    ```bash
    git clone https://github.com/TolgaTD/ObscuraVision.git
    cd ObscuraVision
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the Application:**
    ```bash
    python app.py
    ```

5.  **Access the Dashboard:**
    Open your browser and navigate to `http://localhost:8000`.

<img width="711" height="911" alt="image" src="https://github.com/user-attachments/assets/8ba422ab-4480-4e3b-a8af-e71e228a1ee7" />



## 🤝 Credits

*   **Developers:** Tolga DEMİREL, Anıl Eray KOCABIYIK, Tuna KARAKÖSE
*   **Tools:** Thanks to the developers of MobSF and VirusTotal.

---
*This project is for academic and educational purposes only.*
