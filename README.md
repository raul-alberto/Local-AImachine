# Court - Local Uncensored AI

Privacy-focused AI running locally on your machine. No data collection, no external servers, and no user tracking. Designed for secure, anonymous interactions while keeping full control of your data.

Created by **Nox**.

## Features

- Local AI processing using Ollama
- Local account system with register/login (SQLite + hashed passwords, no default credentials)
- Dark, responsive UI on one shared stylesheet with seven switchable color themes
- ChatGPT-like interface with sidebar chat history
- Model name and live Ollama health status in the header
- Streaming responses with stop/cancel control
- Advanced generation controls (preset, temperature, top_p, top_k, max tokens)
- Local RAG knowledge base (upload files, retrieve context, cite sources)
- RAG document manager (rename/delete indexed files)
- Privacy mode toggle (ephemeral vs persistent chats)
- One-click local data wipe per account
- Animated loading indicators with custom logo
- Markdown responses with offline syntax highlighting and copy buttons
- FAQs page

## What You Need

Before first run, make sure you have:

- Windows 10/11, macOS, or Linux
- Python 3.11 or newer
- Ollama installed locally (https://ollama.com/download)
- At least 16 GB RAM recommended for larger models
- Optional: NVIDIA GPU for faster local inference/training

## First-Time Setup (Step-by-Step)

The steps below are written for Windows PowerShell.

1. Install Ollama

   Download and install from https://ollama.com/download

2. Verify Ollama is available

   ```powershell
   ollama --version
   ```

3. Pull a model (required before app launch)

   ```powershell
   ollama pull godmoded/llama3-lexi-uncensored:latest
   ```

4. Clone this repository (if not already cloned)

   ```powershell
   git clone https://github.com/noxium-git/Local-AImachine.git
   cd Local-AImachine
   ```

5. Create and activate a virtual environment

   ```powershell
   py -3.11 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

6. Install Python dependencies

   ```powershell
   pip install -r requirements.txt
   ```

7. Start the app

   ```powershell
   python launcher.py
   ```

8. Open the app

   Visit http://localhost:5000

9. Create your account

   Court ships no default credentials. On first launch it opens the
   registration page: pick a username and a password of at least 8
   characters, then sign in with them.

## Network Access

Court listens on `127.0.0.1:5000` by default, so only this computer can open it.

- `python launcher.py --lan` (or `COURT_HOST=0.0.0.0`) also accepts connections from other devices on your network.
- `--port` (or `COURT_PORT`) changes the port.

Anyone who can reach an exposed instance sees the login page, and registration stays open, so use a strong password.

## Linux Quick Start (Ubuntu/Debian)

1. Install system dependencies

   ```bash
   sudo apt update
   sudo apt install -y python3 python3-venv python3-pip git
   ```

2. Install Ollama

   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ollama --version
   ```

3. Clone the repo

   ```bash
   git clone https://github.com/noxium-git/Local-AImachine.git
   cd Local-AImachine
   ```

4. Create and activate a virtual environment

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

5. Install dependencies and pull model

   ```bash
   pip install -r requirements.txt
   ollama pull godmoded/llama3-lexi-uncensored:latest
   ```

6. Start app

   ```bash
   python launcher.py
   ```

## Model Selection

To run with a specific local Ollama model:

```powershell
$env:COURT_MODEL='court-refusal-v2'
python app.py
```

Linux/macOS equivalent:

```bash
export COURT_MODEL='court-refusal-v2'
python app.py
```

If the UI shows model missing, confirm:

```powershell
ollama list
```

## Evaluate Before Training

Run the local benchmark harness before you fine-tune:

1. Edit prompt cases in `eval_prompts.json`.
2. Run:
   ```
   python eval_runner.py
   ```
3. Review `eval_report.json` for latency and response quality preview.

## Refusal Reduction Workflow

Use this workflow to reduce false refusals while preserving refusals for clearly harmful requests.

1. Build dataset:
   ```
   python training_data/build_refusal_reduction_dataset.py
   ```
2. Evaluate baseline model:
   ```
   python eval_runner.py --model godmoded/llama3-lexi-uncensored:latest --report training_data/eval_report_baseline.json
   ```
3. Create Court policy model:
   ```
   python training_data/create_court_refusal_model.py --base godmoded/llama3-lexi-uncensored:latest --target court-refusal-v1
   ```
4. Evaluate policy model:
   ```
   python eval_runner.py --model court-refusal-v1 --report training_data/eval_report_target.json
   ```
5. Run full pipeline in one command:
   ```
   python training_data/run_refusal_pipeline.py
   ```
6. Launch app with target model:
   ```powershell
   $env:COURT_MODEL='court-refusal-v1'
   python app.py
   ```
   Linux/macOS:
   ```bash
   export COURT_MODEL='court-refusal-v1'
   python app.py
   ```

## Local RAG Quick Start

1. Open Settings in chat.
2. In `Local knowledge`, tick `Enable document retrieval in chat responses`.
3. Index a local file (`.txt`, `.md`, `.py`, `.json`, `.csv`, `.html`, `.js`, `.css`, `.pdf`).
4. Ask a question related to the uploaded content.
5. Court will include a `Sources` section when context is used.
6. Use `View sources` on AI messages to inspect matched snippets.

## Privacy Controls

In Settings:

1. Choose `Privacy mode`:
   - `Ephemeral`: chats are deleted from this device when you log out.
   - `Persistent`: chats are saved locally per user.
2. Use `Wipe local data` to clear chats, indexed docs, and reset settings for the current account.
3. Failed logins are throttled: after 5 misses from the same address and username within 15 minutes, sign-in is locked for 60 seconds, doubling on each further miss.

## Packaging

To create a local Windows package and installer:

1. Install dependencies:
   ```
   pip install pyinstaller
   ```
2. Run the build script:
   ```
   .\package.ps1
   ```
3. After building, open `BettenAIInstaller.iss` in Inno Setup and compile it to generate a Windows installer.
4. Make sure Ollama is installed locally and the model is downloaded before distributing the app.
5. Court generates a per-install session key in `.court_secret` on first run. Set `COURT_SECRET_KEY` to supply your own instead.

## Project Structure

- `app.py`: Main Flask application
- `templates/`: HTML templates (login, register, chat, faqs)
- `static/`: shared stylesheet, images, and the vendored highlight.js build and theme (`vendor/`, BSD-3-Clause) used for offline code highlighting
- `requirements.txt`: Python dependencies

## Usage

- Start new chats from the sidebar
- View chat history in the left panel
- Access FAQs for more information
- AI responses render Markdown with syntax-highlighted code and a copy button

Enjoy your creative AI companion!
