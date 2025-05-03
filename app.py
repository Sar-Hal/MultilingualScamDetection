from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import google.generativeai as genai
import os
import requests
import re
import json
from googleapiclient.discovery import build
from faster_whisper import WhisperModel
import tempfile
import logging
import pyttsx3
from tenacity import retry, stop_after_attempt, wait_fixed
from typing import Tuple, Dict, List, Any
from functools import lru_cache
from dotenv import load_dotenv
from langdetect import detect, LangDetectException
import threading
import uvicorn

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create directories
os.makedirs("static", exist_ok=True)
os.makedirs("audio", exist_ok=True)

# Load environment variables
load_dotenv()

app = FastAPI(title="Hybrid Multilingual Scam Detection API", version="1.1.0")

# CORS middleware (from Code 1)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Mount static directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Configure API keys
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
google_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

# Language to alert audio mapping (from Code 2)
ALERT_AUDIOS = {"en": "alert_en.mp3", "fr": "alert_fr.mp3", "es": "alert_es.mp3", "pt": "alert_pt.mp3", "hi": "alert_hi.mp3"}

# Input model
class ContentInput(BaseModel):
    content: str

# Detect language (from Code 2)
def detect_language(text: str) -> str:
    try:
        return detect(text)
    except LangDetectException:
        logger.warning(f"Language detection failed for text: {text[:50]}...")
        return "en"

# Scam detection with caching (from Code 2) and detailed output (from Code 1)
@lru_cache(maxsize=1000)
def check_scam(content: str, lang: str) -> Tuple[bool, Dict]:
    content = content.strip()
    if not content:
        return False, {"risk_level": "Error", "confidence_score": 0, "detected_patterns": [], "justification": "Empty content provided"}
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
    for url in urls:
        if check_url(url):
            return True, {
                "risk_level": "Scam",
                "confidence_score": 9,
                "detected_patterns": [{"category": "Phishing Patterns", "examples_found": [f"Malicious URL: {url}"]}],
                "justification": f"Malicious URL detected - {url}"
            }
    scam_phrases = {
        "en": ["win a prize", "urgent action required"], "fr": ["gagnez un prix", "action urgente requise"],
        "hi": ["पुरस्कार जीतें", "तत्काल कार्रवाई आवश्यक"]
    }
    lang_phrases = scam_phrases.get(lang, scam_phrases["en"])
    prompt = f"""
    Analyze this message for scam indicators across categories like Urgency & Fear Tactics, Financial Requests, Phishing Patterns.
    Message: {content}
    Output Format (JSON):
    {{
        "risk_level": "Safe/Suspicious/Scam",
        "confidence_score": 0-10,
        "detected_patterns": [
            {{"category": "Financial Requests", "examples_found": ["Request for Bitcoin wallet address"]}}
        ],
        "justification": "Concise explanation in user's language"
    }}
    Look for phrases like {', '.join(lang_phrases)}.
    """
    try:
        model = genai.GenerativeModel("gemini-1.5-pro")
        response = model.generate_content(prompt, generation_config=genai.types.GenerationConfig(response_mime_type="application/json"))
        result = json.loads(response.text)
        return (result["risk_level"] == "Scam", result)
    except Exception as e:
        logger.error(f"Gemini API error: {str(e)}")
        return False, {"risk_level": "Error", "confidence_score": 0, "detected_patterns": [], "justification": f"Error: {str(e)}"}

# URL safety check (from Code 2)
@lru_cache(maxsize=1000)
def check_url(url: str) -> bool:
    try:
        service = build("safebrowsing", "v4", developerKey=google_api_key)
        threats = service.threatMatches().find(body={
            "client": {"clientId": "yourcompany", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"],
                           "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}
        }).execute()
        return bool(threats.get("matches"))
    except Exception as e:
        logger.error(f"Safe Browsing API error: {str(e)}")
        return False

# Audio transcription with retry (from Code 2)
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def transcribe_audio(audio_file_path: str) -> Tuple[str, str]:
    try:
        model = WhisperModel("base", device="cpu")
        segments, info = model.transcribe(audio_file_path, beam_size=5, language=None)
        text = " ".join(segment.text for segment in segments)
        return text or "No speech detected", info.language if info.language else "en"
    except Exception as e:
        logger.error(f"Transcription failed: {str(e)}")
        return f"Error: {str(e)}", "en"

# Dynamic audio alert generation (from Code 1)
def generate_audio_alert(message: str, lang: str) -> str:
    try:
        alert_file = ALERT_AUDIOS.get(lang, "alert.mp3")
        alert_path = os.path.join("static", alert_file)
        if not os.path.exists(alert_path):
            engine = pyttsx3.init()
            engine.save_to_file(message, alert_path)
            engine.runAndWait()
        return f"/static/{alert_file}"
    except Exception as e:
        logger.error(f"Audio alert failed: {str(e)}")
        return ""

# Endpoints from Code 1 with detailed output
@app.post("/scan/text")
async def scan_text(message: str = Form(...)):
    lang = detect_language(message)
    is_scam, result = check_scam(message, lang)
    if is_scam:
        result["audio_alert"] = generate_audio_alert(result["justification"], lang)
    return result

@app.post("/scan/voice")
async def scan_voice(file: UploadFile = File(...)):
    temp_path = tempfile.NamedTemporaryFile(suffix=".wav", delete=False).name
    with open(temp_path, "wb") as f:
        f.write(await file.read())
    text, lang = transcribe_audio(temp_path)
    os.remove(temp_path)
    is_scam, result = check_scam(text, lang)
    if is_scam:
        result["audio_alert"] = generate_audio_alert(result["justification"], lang)
    return result

@app.post("/scan/url")
async def scan_url(url: str = Form(...)):
    is_scam = check_url(url)
    result = {
        "url": url,
        "risk": "Scam" if is_scam else "Safe",
        "details": []
    }
    if is_scam:
        result["audio_alert"] = generate_audio_alert(f"Warning: Malicious URL detected - {url}", "en")
    return result

# Server execution
def run_server():
    uvicorn.run(app, host="0.0.0.0", port=8001)

if __name__ == "__main__":
    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    
    # Testing endpoints (from Code 1)
    test_message = "VERIFY your account http://fake-paypal-login.in"
    response = requests.post("http://localhost:8001/scan/text", data={"message": test_message})
    print("Text scan test:", response.json())
    
    test_url = "https://www.google.com"
    response = requests.post("http://localhost:8001/scan/url", data={"url": test_url})
    print("URL scan test:", response.json())
