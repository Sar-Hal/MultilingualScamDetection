from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import google.genai as genai  # Updated import as per previous guidance
import os
import requests
import re
import json
from googleapiclient.discovery import build
from faster_whisper import WhisperModel
import tempfile
import logging
from tenacity import retry, stop_after_attempt, wait_fixed
from typing import Tuple, Dict
from functools import lru_cache
from dotenv import load_dotenv
from langdetect import detect, LangDetectException
import uvicorn

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create directories with error handling for Render's ephemeral filesystem
try:
    os.makedirs("static", exist_ok=True)
    os.makedirs("audio", exist_ok=True)
    logger.info("Created static and audio directories")
except Exception as e:
    logger.error(f"Failed to create directories: {str(e)}")

# Load environment variables
load_dotenv()

# Initialize FastAPI with root_path if needed (adjust based on Render proxy if applicable)
app = FastAPI(title="Hybrid Multilingual Scam Detection API", version="1.1.0")

# CORS middleware
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Mount static directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Configure API keys from environment variables
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))  # Updated to match correct env var
google_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

# Language to alert audio mapping
ALERT_AUDIOS = {"en": "alert_en.wav", "fr": "alert_fr.wav", "es": "alert_es.wav", "pt": "alert_pt.wav", "hi": "alert_hi.wav"}

# Add a root endpoint for health check (suggested by search result [6])
@app.get("/", summary="Health Check")
async def root():
    return {"status": "API is running", "message": "Welcome to the Scam Detection API. Use /scan/text, /scan/voice, or /scan/url endpoints."}
# Input model
class ContentInput(BaseModel):
    content: str

# Detect language
def detect_language(text: str) -> str:
    try:
        return detect(text)
    except LangDetectException:
        logger.warning(f"Language detection failed for text: {text[:50]}...")
        return "en"

# Scam detection with caching
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

# URL safety check
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

# Audio transcription with retry
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

# Simplified audio alert generation for Render (avoiding pyttsx3 due to compatibility issues)
def generate_audio_alert(report: Dict, lang: str) -> str:
    try:
        alert_file = ALERT_AUDIOS.get(lang, "alert_en.wav")
        alert_path = os.path.join("static", alert_file)
        # For Render, return a placeholder or pre-uploaded audio URL since pyttsx3 may not work
        logger.info(f"Audio alert generation skipped on Render; using placeholder for {alert_file}")
        return f"/static/{alert_file}"
    except Exception as e:
        logger.error(f"Audio alert failed: {str(e)}")
        return ""
    
@app.post("/scan/text")
async def scan_text(message: str = Form(...)):
    lang = detect_language(message)
    is_scam, result = check_scam(message, lang)
    if is_scam or result["risk_level"] == "Suspicious":
        result["audio_alert"] = generate_audio_alert(result, lang)
    return result

@app.post("/scan/voice")
async def scan_voice(file: UploadFile = File(...)):
    temp_path = tempfile.NamedTemporaryFile(suffix=".wav", delete=False).name
    with open(temp_path, "wb") as f:
        f.write(await file.read())
    text, lang = transcribe_audio(temp_path)
    os.remove(temp_path)
    is_scam, result = check_scam(text, lang)
    if is_scam or result["risk_level"] == "Suspicious":
        result["audio_alert"] = generate_audio_alert(result, lang)
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
        report = {"risk_level": "Scam", "confidence_score": 9, "justification": f"Malicious URL detected - {url}", "detected_patterns": []}
        result["audio_alert"] = generate_audio_alert(report, "en")
    return result

if __name__ == "__main__":
    # Use Render's PORT environment variable or default to 8000
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)