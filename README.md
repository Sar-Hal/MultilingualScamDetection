# Multilingual Scam Detection Agent  
AI-powered fraud detection system supporting text, URLs, and voice analysis across 5 languages.

## **Features**  
✅ **Text Analysis**: Phishing/urgency detection in EN, FR, HI, ES, PT  
🌐 **URL Check**: Real-time Google Safe Browsing verification  
🎙️ **Voice Scan**: Audio transcription + text analysis  
🔔 **Multilingual Alerts**: Audio warnings in user's language  
📡 **API Endpoints**: Easy integration via RESTful API

## **Tech Stack**  
`Python` `FastAPI` `Gemini 1.5 Pro` `WhisperModel` `Google Safe Browsing` `pyttsx3`

## **API Structure**
| Endpoint | Method | Functionality |
|----------|--------|---------------|
| `/scan/text` | POST | Text content analysis |
| `/scan/url` | POST | URL safety check |
| `/scan/voice` | POST | Audio scam detection |

Example Request
curl -X POST https://your-app-url.onrender.com/scan/text
-F "message=Congratulations! Click this link to win a prize."



## **Workflow**  
1. **Text**: Language detection → Gemini analysis  
2. **URL**: Google threat database check  
3. **Voice**: Audio transcription → text analysis

## **Key Outcomes**  
✔️ Integrated multi-model detection system  
✔️ 5-language support with audio alerts  
✔️ Scalable backend with error handling

## **Roadmap**  
🔜 WhatsApp integration  
🔜 Expanded language support  
🔜 Enhanced frontend accessibility

**License**: MIT  
_Built with ❤️ by TimeLimitExceeded_
