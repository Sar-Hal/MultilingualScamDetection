from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import google.generativeai as genai
from langdetect import detect
import requests
import json
import os
import logging
import re
import base64
import speech_recognition as sr
import pyttsx3
from dotenv import load_dotenv
import nest_asyncio
import threading
import uvicorn

nest_asyncio.apply()

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

app = FastAPI()

# Mount static directory for audio alerts
app.mount("/static", StaticFiles(directory="."), name="static")

# CORS middleware for broader access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure Gemini
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel('gemini-2.0-flash')

# Google Safe Browsing API
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

# Input model for content detection
class ContentInput(BaseModel):
    content: str

def translate_text(text: str, src: str, dest: str) -> str:
    """Mock translation function for testing"""
    return f"[Translated from {src} to {dest}] {text}"

def analyze_text(text: str) -> dict:
    lang = detect(text)
    if lang != 'en':
        text = translate_text(text, src=lang, dest='en')
    
    # Extract URLs using RE from main.py for initial check
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    for url in urls:
        if check_url(url):
            return {
                "risk_level": "Scam",
                "confidence_score": 9,
                "detected_patterns": [{"category": "Phishing Patterns", "examples_found": [f"Malicious URL: {url}"]}],
                "justification": "Malicious URL detected via Safe Browsing API."
            }

    prompt = f"""
    Analyze this message for scam indicators across categories like Urgency & Fear Tactics, Financial Requests, Phishing Patterns, etc.
    Message: {text}
    Output Format (JSON):
    {{
        "risk_level": "Safe/Suspicious/Scam",
        "confidence_score": 0-10,
        "detected_patterns": [
            {{"category": "Financial Requests", "examples_found": ["Request for Bitcoin wallet address"]}}
        ],
        "justification": "Concise explanation in user's language"
    }}
    """
    try:
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(response_mime_type="application/json")
        )
        result = json.loads(response.text)
        if lang != 'en':
            result['justification'] = translate_text(result['justification'], src='en', dest=lang)
        return result
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        return error_response(str(e))

def error_response(message: str = "Analysis failed") -> dict:
    return {
        "risk_level": "Error",
        "confidence_score": 0,
        "detected_patterns": [],
        "justification": message
    }

def check_url(url: str) -> bool:
    """Check URL safety using Google Safe Browsing API"""
    try:
        api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {
            "client": {"clientId": "your-app-name", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        params = {"key": GOOGLE_SAFE_BROWSING_API_KEY}
        response = requests.post(api_url, params=params, json=payload)
        response.raise_for_status()
        data = response.json()
        return bool(data.get("matches"))
    except Exception as e:
        logger.error(f"URL check failed: {str(e)}")
        return False

def transcribe_voice(audio_file_bytes: bytes) -> str:
    """Transcribe audio using Gemini model"""
    try:
        # Note: Consider dynamically setting the mime_type based on the uploaded file.
        response = model.generate_content([
            "Transcribe this audio message",
            {
                "inline_data": {
                    "mime_type": "audio/webm", # Assuming webm format for now
                    "data": base64.b64encode(audio_file_bytes).decode()
                }
            }
        ])
        return response.text
    except Exception as e:
        logger.error(f"Transcription failed: {str(e)}")
        raise

def transcribe_audio_offline(audio_file_path: str) -> str:
    """Offline transcription using CMU Sphinx from main.py"""
    recognizer = sr.Recognizer()
    with sr.AudioFile(audio_file_path) as source:
        audio = recognizer.record(source)
    try:
        text = recognizer.recognize_sphinx(audio, language="en-US")
        return text
    except sr.UnknownValueError:
        return "Could not understand audio"
    except sr.RequestError as e:
        return f"Error: {e}"

def generate_audio_alert(message: str) -> str:
    """Generate audio alert using pyttsx3 from main.py"""
    engine = pyttsx3.init()
    audio_path = "alert.mp3"
    engine.save_to_file(message, audio_path)
    engine.runAndWait()
    return f"/static/{audio_path}"

@app.post("/scan/text")
async def scan_text(message: str = Form(...)):
    try:
        logger.info(f"Scanning text: {message[:50]}...")
        result = analyze_text(message)
        if result["risk_level"] == "Scam":
            result["audio_alert"] = generate_audio_alert(result["justification"])
        return result
    except Exception as e:
        logger.error(f"Text scan error: {str(e)}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/scan/voice")
async def scan_voice(file: UploadFile = File(...)):
    try:
        logger.info("Processing voice note...")
        audio_bytes = await file.read()
        text = transcribe_voice(audio_bytes)
        result = analyze_text(text)
        if result["risk_level"] == "Scam":
            result["audio_alert"] = generate_audio_alert(result["justification"])
        return result
    except Exception as e:
        logger.error(f"Voice scan error: {str(e)}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/scan/url")
async def scan_url(url: str = Form(...)):
    try:
        logger.info(f"Scanning URL: {url}")
        is_scam = check_url(url)
        risk = "Scam" if is_scam else "Safe"
        result = {"url": url, "risk": risk, "details": []}
        if is_scam:
            result["audio_alert"] = generate_audio_alert(f"Warning: Malicious URL detected - {url}")
        return result
    except Exception as e:
        logger.error(f"URL scan error: {str(e)}")
        return JSONResponse(status_code=500, content={"error": f"URL check failed: {str(e)}"})

@app.post("/webhook")
async def whatsapp_webhook(payload: dict):
    """WhatsApp webhook integration from main.py"""
    try:
        if payload.get("object") == "whatsapp_business_account":
            for entry in payload.get("entry", []):
                for change in entry.get("changes", []):
                    value = change.get("value", {})
                    if messages := value.get("messages", []):
                        for message in messages:
                            text = message.get("text", {}).get("body", "")
                            audio = message.get("audio", {}).get("id", "")
                            if text:
                                result = analyze_text(text)
                                is_scam = result["risk_level"] == "Scam"
                            elif audio:
                                audio_url = download_whatsapp_audio(audio, os.getenv("WHATSAPP_TOKEN"))
                                transcribed_text = transcribe_audio_offline(audio_url)
                                result = analyze_text(transcribed_text)
                                is_scam = result["risk_level"] == "Scam"
                            else:
                                continue
                            if is_scam:
                                send_whatsapp_response(
                                    message["from"],
                                    f"⚠️ Scam Detected: {result['justification']}",
                                    os.getenv("WHATSAPP_TOKEN"),
                                    os.getenv("WHATSAPP_PHONE_NUMBER_ID")
                                )
        return {"status": "received"}
    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

def download_whatsapp_audio(audio_id: str, token: str) -> str:
    """Download WhatsApp audio from main.py"""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"https://graph.facebook.com/v13.0/{audio_id}", headers=headers)
    audio_url = response.json().get("url")
    audio_response = requests.get(audio_url, headers=headers)
    with open("temp_audio.wav", "wb") as f:
        f.write(audio_response.content)
    return "temp_audio.wav"

def send_whatsapp_response(to: str, message: str, token: str, phone_number_id: str):
    """Send WhatsApp response from main.py"""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": message}
    }
    requests.post(f"https://graph.facebook.com/v13.0/{phone_number_id}/messages", json=payload, headers=headers)

def run_server():
    uvicorn.run(app, host="0.0.0.0", port=8001)

if __name__ == "__main__":
    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    
    # Testing endpoints as in original scam_detection.py
    response = requests.post(
        "http://localhost:8001/scan/text",
        data={"message": "VERIFY your account http://fake-paypal-login.in"}
    )
    print("Text scan test:", response.json())
    
    test_url = "https://www.google.com"
    response = requests.post(
        "http://localhost:8001/scan/url",
        data={"url": test_url}
    )
    print("URL scan test:", response.json())
    
    try:
        with open("test_voice.wav", "rb") as f:
            files = {"file": ("voice.wav", f, "audio/wav")}
            response = requests.post(
                "http://localhost:8001/scan/voice",
                files=files,
                timeout=30
            )
            print("Status Code:", response.status_code)
            print("Response:", response.json())
    except FileNotFoundError:
        print("Test voice file not found.")
