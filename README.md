# AI-Powered Web Vulnerability Scanner

A modern, open-source web vulnerability scanner that combines traditional heuristic scanning with the power of Large Language Models (LLMs) to detect complex security issues.

![Scanner Interface](https://via.placeholder.com/800x400?text=AI+Scanner+Interface)

## 🚀 How It Works

This project utilizes a three-layered approach to security analysis:

1.  **Smart Crawler**:
    -   Maps the target website structure.
    -   Respects `robots.txt` (configurable) and depth limits.
    -   Identifies input vectors (forms, URL parameters).

2.  **Heuristic Engine**:
    -   Performs fast, static checks for common misconfigurations.
    -   Detects missing security headers (CSP, X-Frame-Options).
    -   Identifies insecure forms (HTTP, missing CSRF tokens).

3.  **AI Analysis Engine**:
    -   Leverages **OpenAI (GPT-4)** or **Google Gemini** models.
    -   Analyzes page context and code snippets for logic flaws.
    -   Detects subtle issues like XSS, sensitive data exposure, and insecure comments that regex-based scanners miss.

## ⚖️ Merits & Demerits

### Merits
-   **Context-Aware**: AI understands the *intent* of code, not just patterns.
-   **Modern UI**: Sleek, dark-mode interface with real-time visualization.
-   **Extensible**: Modular architecture allows easy addition of new checks.
-   **Open Source**: Community-driven development and transparency.

### Demerits
-   **AI Hallucinations**: LLMs can sometimes report false positives. Always verify findings manually.
-   **Cost/Rate Limits**: Requires an API key (OpenAI/Gemini), which may incur costs or hit rate limits.
-   **Performance**: AI analysis is slower than traditional static scanning.

## ⚠️ Ethical Use Warning

> **IMPORTANT**: This tool is intended for **EDUCATIONAL PURPOSES** and **AUTHORIZED SECURITY TESTING** only.

-   **Do not** scan websites you do not own or have explicit permission to test.
-   **Do not** use this tool for malicious purposes.
-   The developers assume **no liability** for any damage caused by the misuse of this software.

## 🛠️ Usage

### Prerequisites
-   Python 3.10+
-   An API Key (OpenAI or Google Gemini)

### Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/AyushPatil1234/web.git
    cd web
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the application**:
    ```bash
    python3 server.py
    ```

4.  **Access the Dashboard**:
    Open your browser and navigate to `http://localhost:5000`.

### Deployment
This project is configured for easy deployment on **Render**.
1.  Fork this repo.
2.  Create a new Web Service on Render.
3.  Connect your repo.
4.  Render will automatically use `render.yaml` to build and deploy.

## 🤝 Contributing

This is an **Open Source** project! We welcome contributions from the community.

1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
