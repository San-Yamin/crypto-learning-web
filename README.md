# Crypto Escape Room

Crypto Escape Room is a lightweight Flask app that teaches core cryptography concepts through short, self‑contained puzzle modules. Each module includes a mission prompt, a tooling link, and curated reference links so learners can solve the question with guided help.

## Features
- 18 interactive modules across crypto foundations, algorithms, and protocols
- Built‑in verification for each answer
- Tool links and reference materials for every module
- Clean, single‑page module flow

## Tech Stack
- Python 3
- Flask
- HTML/CSS/JS (templates + static assets)

## Getting Started
1. Create a virtual environment (optional but recommended)
2. Install dependencies
3. Run the app

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Project Structure
- /Users/sanyamin/Desktop/crypto-learning-web/app.py
- /Users/sanyamin/Desktop/crypto-learning-web/templates/index.html
- /Users/sanyamin/Desktop/crypto-learning-web/templates/module.html
- /Users/sanyamin/Desktop/crypto-learning-web/static/css/style.css
- /Users/sanyamin/Desktop/crypto-learning-web/static/js/main.js
- /Users/sanyamin/Desktop/crypto-learning-web/ANSWERS.txt

## Modules Overview
1. Introduction to InfoSec (CIA triad + Base64)
2. Math Foundations (modular equation)
3. Encryption Paradigms (asymmetric vs symmetric)
4. Advanced Math (Fermat’s Little Theorem)
5. Probability & Number Theory (GCD)
6. Number‑Theoretic Problems (factorization)
7. RSA & Quadratic Residuosity (private key)
8. Parameters & Primality (Miller‑Rabin)
9. Prime Generation & Stream Ciphers (XOR)
10. LFSRs (next state)
11. Block Ciphers (ECB pattern leakage)
12. Classical Evolution (Caesar cipher)
13. Core Public‑Key Algorithms (ElGamal)
14. Hash Functions (SHA‑256)
15. Identification & Authentication (dictionary attack)
16. Extended Euclidean Algorithm (x,y coefficients)
17. Modular Exponentiation (square‑and‑multiply)
18. Rabin Public‑Key Encryption (m^2 mod n)

## Updating Modules
All module content lives in `MODULE_DATA` in `/Users/sanyamin/Desktop/crypto-learning-web/app.py`. Each module supports:
- `title`, `type`, `theory`
- `tool_name`, `external_tool_url`
- `mission_cipher`, `correct_answer`, `hint`
- `reference_links` (list of `{label, url}`)

## Answer Key
See `/Users/sanyamin/Desktop/crypto-learning-web/ANSWERS.txt` for a full answer list.

## Notes
- Reference links are curated to match each mission.
- Tools are chosen to directly compute or verify the required result.

If you want to add new modules or change the format, update `MODULE_DATA` and the UI will render them automatically.
