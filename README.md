\# 🔐 Phishing URL Detector

## 🚀 Live Demo

👉 [Try the Phishing URL Detector](https://phishing-url-detector-ae7r.onrender.com)



A beginner-friendly cybersecurity web application that analyzes URLs and identifies common indicators associated with phishing or suspicious websites.



The application uses heuristic-based rules to calculate a risk score and provides an easy-to-understand security assessment.



\---



\## 🚀 Features



\- 🔎 Analyze a URL for suspicious indicators

\- 📊 Calculate a risk score

\- 🟢 Identify URLs as \*\*Likely Safe\*\*

\- 🟠 Identify URLs as \*\*Suspicious\*\*

\- 🔴 Identify URLs as \*\*High Risk\*\*

\- 🌐 Check whether HTTPS is being used

\- 🔢 Detect IP addresses used instead of domain names

\- 🔑 Detect suspicious keywords such as:

&#x20; - login

&#x20; - verify

&#x20; - account

&#x20; - password

&#x20; - secure

\- 🚪 Detect uncommon ports

\- 🌳 Detect excessive subdomains

\- 📜 Maintain scan history

\- 🗑️ Clear scan history

\- 📱 Responsive web interface



\---



\## 🛠️ Technologies Used



\### Backend

\- Python

\- Flask



\### Frontend

\- HTML

\- CSS

\- JavaScript



\### Development Tools

\- VS Code

\- Git

\- GitHub

\- Python Virtual Environment



\---



\## 🧠 How It Works



The application analyzes different characteristics of the submitted URL.



Examples of suspicious indicators include:



1\. \*\*No HTTPS\*\*

&#x20;  - The URL uses HTTP instead of HTTPS.



2\. \*\*IP Address\*\*

&#x20;  - The URL uses an IP address instead of a normal domain name.



3\. \*\*Suspicious Keywords\*\*

&#x20;  - Words such as `login`, `verify`, `account`, or `password` may indicate a suspicious URL.



4\. \*\*Uncommon Port\*\*

&#x20;  - Ports such as `8080`, `8888`, or `9999` may increase the risk score.



5\. \*\*Excessive Subdomains\*\*

&#x20;  - Multiple nested subdomains can sometimes be used to make malicious URLs appear legitimate.



Each detected indicator contributes to the overall risk score.



\---



\## 📊 Risk Levels



| Risk Score | Result |

|------------|--------|

| 0–19% | 🟢 Likely Safe |

| 20–49% | 🟠 Suspicious |

| 50%+ | 🔴 High Risk |



> \*\*Note:\*\* This project uses heuristic rules. A "Likely Safe" result does not guarantee that a website is safe, and a suspicious result does not prove that a website is malicious.



\---



\## 📂 Project Structure



```text

phishing-url-detector/

│

├── app.py

├── requirements.txt

├── .gitignore

│

├── templates/

│   └── index.html

│

├── static/

│   └── style.css

│

└── venv/

