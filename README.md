
Built by https://www.blackbox.ai

---

# Website Legitimacy Checker

## Project Overview

The **Website Legitimacy Checker** is a Flask web application designed to analyze the legitimacy and safety of websites entered by users. It utilizes external API services such as Google Safe Browsing and VirusTotal to provide a detailed analysis, including risk scores and recommendations based on the safety of the provided URL. This tool aims to help users identify potentially unsafe websites before visiting them.

## Installation

To set up the project locally, follow these steps:

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your-username/website-legitimacy-checker.git
   cd website-legitimacy-checker
   ```

2. **Create a virtual environment:**

   On macOS/Linux:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

   On Windows:

   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install the required dependencies:**

   Make sure you have `pip` installed, then run:

   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables:**

   You will need API keys for Google Safe Browsing and VirusTotal. Set them as environment variables:

   ```bash
   export GOOGLE_SAFE_BROWSING_API_KEY='your_google_api_key'
   export VIRUSTOTAL_API_KEY='your_virustotal_api_key'
   ```

   On Windows, you can set them using:

   ```bash
   set GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key
   set VIRUSTOTAL_API_KEY=your_virustotal_api_key
   ```

5. **Run the application:**

   ```bash
   python app.py
   ```

   Navigate to `http://127.0.0.1:8080` in your web browser to access the application.

## Usage

1. **Enter a URL** in the input field on the home page.
2. Click the **"Analyze"** button to submit your URL.
3. The application will process the URL and display the analysis results, including any threats found and recommendations.

## Features

- User-friendly interface to input and analyze URLs.
- Integrates with Google Safe Browsing for threat detection.
- Utilizes VirusTotal for a comprehensive analysis of safety based on multiple antivirus engines.
- Displays results such as legitimacy, risk score, and detailed findings.
- Provides SSL certificate validation and domain age checks.

## Dependencies

The project uses the following Python packages, which are listed in `requirements.txt`:

- Flask: Web framework for building the application.
- validators: For validating URL formats.
- requests: For making HTTP requests to external APIs.
- whois (optional, not listed in requirements.txt): For checking domain age.
- ssl and socket (standard libraries): For SSL certificate validation.

Make sure to install the dependencies mentioned above to run the project successfully.

## Project Structure

The project is structured as follows:

```
website-legitimacy-checker/
│
├── app.py                      # Main Flask application file.
├── templates/                  # Contains HTML templates.
│   ├── index.html              # Home page template.
│   └── result.html             # Result page template showing analysis.
├── requirements.txt            # List of project dependencies.
└── README.md                   # Project documentation.
```

## Conclusion

The Website Legitimacy Checker serves as an essential tool for web users to enhance their online safety by analyzing the legitimacy of URLs. By leveraging powerful APIs and providing insightful analysis, this application helps users make informed decisions about the websites they visit.