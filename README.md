Multilingual Scam Detection Agent
Overview
The Multilingual Scam Detection Agent is an AI-powered system that analyzes text, URLs, and voice inputs to identify scam content across multiple languages. Designed for accessibility and security, it leverages state-of-the-art machine learning models and cybersecurity APIs to help users detect phishing, fraud, and malicious links.

Features
Text Scam Detection: Analyze messages for phishing, urgency, and scam indicators in English, French, Hindi, Spanish, and Portuguese.

URL Safety Check: Instantly check URLs against Google’s Safe Browsing threat database.

Voice Scam Detection: Transcribe audio messages and analyze the text for scam patterns.

Multilingual Alerts: Generates audio alerts in the user’s language when a scam is detected.

RESTful API: Three endpoints for easy integration: /scan/text, /scan/url, /scan/voice.

Technology Stack
Backend: FastAPI (Python)

ML Models:

Gemini 1.5 Pro (scam content analysis)

faster-whisper (WhisperModel for voice transcription)

APIs: Google Safe Browsing (malicious URL detection)

Other Tools: pyttsx3 (audio alerts), langdetect (language detection), Render (deployment)

API Endpoints
Endpoint	Method	Description
/scan/text	POST	Analyze text for scam indicators.
/scan/url	POST	Check if a URL is malicious or suspicious.
/scan/voice	POST	Transcribe audio and analyze the resulting text for scam patterns.
Example Request (Text):

bash
curl -X POST https://your-app-url.onrender.com/scan/text \
     -F "message=Congratulations! Click this link to win a prize."
How It Works
Text: Detects language, analyzes for scam tactics using Gemini 1.5 Pro.

URL: Checks against Google’s threat database.

Voice: Transcribes audio using faster-whisper, then analyzes the text.

Alerts: If a scam is detected, an audio alert is generated and returned.

What Worked Well
Seamless integration of multiple AI models and APIs.

Reliable detection across five languages and three input types.

Scalable and robust backend with error handling and caching.

Challenges
Real-time, accurate voice transcription under resource constraints.

Handling nuanced scam tactics in multiple languages.

Full WhatsApp integration was not completed due to API/time limits.

Future Work
Complete WhatsApp integration for direct message-based scam checking.

Expand language coverage and improve scam detection accuracy.

Enhance the frontend for wider accessibility.


License
MIT License



Built with ❤️ by TimeLimitExceeded
