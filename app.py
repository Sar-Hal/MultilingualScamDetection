from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import google.generativeai as genai  # Correct import
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

# Create directories
try:
    os.makedirs("static", exist_ok=True)
    os.makedirs("audio", exist_ok=True)
    logger.info("Created static and audio directories")
except Exception as e:
    logger.error(f"Directory creation failed: {str(e)}")

# Load environment variables
load_dotenv()

# Initialize FastAPI
app = FastAPI(title="Scam Detection API", version="1.1.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],  # Explicitly allow all methods
    allow_headers=["*"]
)


# Mount static directory
app.mount("/static", StaticFiles(directory="static"), name="static")

# Configure GenAI
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))  # Use correct env var name
google_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {
        "status": "API operational",
        "endpoints": ["/scan/text", "/scan/voice", "/scan/url"]
    }
# Language mappings
ALERT_AUDIOS = {
    "en": "alert_en.wav",
    "fr": "alert_fr.wav",
    "es": "alert_es.wav",
    "pt": "alert_pt.wav",
    "hi": "alert_hi.wav"
}

# Health check endpoint
@app.get("/")
async def root():
    return {"status": "API operational", "endpoints": ["/scan/text", "/scan/voice", "/scan/url"]}

# Input model
class ContentInput(BaseModel):
    content: str

# Language detection
def detect_language(text: str) -> str:
    try:
        return detect(text)
    except LangDetectException:
        logger.warning(f"Language detection failed for text: {text[:50]}...")
        return "en"

# Scam detection core
@lru_cache(maxsize=1000)
def check_scam(content: str, lang: str) -> Tuple[bool, Dict]:
    content = content.strip()
    if not content:
        return False, {"risk_level": "Error", "details": "Empty content"}
    
    # URL check
    urls = re.findall(r'https?://\S+', content)
    for url in urls:
        if check_url(url):
            return True, {
                "risk_level": "Scam",
                "confidence": 9.5,
                "details": f"Malicious URL detected: {url}",
                "type": "phishing"
            }
    
    # Text analysis
    scam_phrases = {
        "en": ["win a prize", "urgent action required"],
        "fr": ["gagnez un prix", "action urgente requise"],
        "hi": ["पुरस्कार जीतें", "तत्काल कार्रवाई आवश्यक"]
    }
    lang_phrases = scam_phrases.get(lang, scam_phrases["en"])
    
    try:
        model = genai.GenerativeModel('gemini-1.5-pro')
        response = model.generate_content(
            f"Analyze for scam indicators in {lang}. Text: {content}",
            generation_config={"response_mime_type": "application/json"}
        )
        result = json.loads(response.text)
        
        # Check if scam_indicators exist and are not empty
        has_indicators = "scam_indicators" in result and len(result["scam_indicators"]) > 0
        
        # Either check for risk_level OR scam_indicators
        is_scam = result.get("risk_level", "").lower() == "scam" or has_indicators
        
        return (is_scam, result)
    except Exception as e:
        logger.error(f"GenAI error: {str(e)}")
        return False, {"error": str(e)}

# URL safety check
@lru_cache(maxsize=1000)
def check_url(url: str) -> bool:
    try:
        service = build("safebrowsing", "v4", developerKey=google_api_key)
        response = service.threatMatches().find(
            body={
                "client": {"clientId": "security", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
        ).execute()
        return bool(response.get("matches"))
    except Exception as e:
        logger.error(f"Safe Browsing API error: {str(e)}")
        return False

# Audio processing
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))

def transcribe_audio(file_path: str) -> Tuple[str, str]:
    try:
        model = WhisperModel(
            "base",
            device="cpu",
            compute_type="int8",  # Required for CPU compatibility
            download_root="/tmp/whisper",
            local_files_only=True  # Prevent redownloading
        )
        
        # Force sample rate conversion for compatibility
        segments, info = model.transcribe(
            file_path,
            beam_size=5,
            vad_filter=True,
            initial_prompt="",  # Disable language auto-detection
            language="en"       # Set explicitly if known
        )
        return " ".join(segment.text for segment in segments), info.language or "en"
    except Exception as e:
        logger.error(f"Transcription failed: {str(e)}")
        return f"Error: {str(e)}", "en"


# Endpoints
@app.post("/scan/text")
async def scan_text(message: str = Form(...)):
    lang = detect_language(message)
    is_scam, result = check_scam(message, lang)
    return {
        "scam": is_scam,
        "language": lang,
        "details": result,
        "audio": f"/static/{ALERT_AUDIOS.get(lang, 'alert_en.wav')}" if is_scam else ""
    }

@app.post("/scan/voice")
async def scan_voice(file: UploadFile = File(...)):
    try:
        # Validate audio format
        if not file.filename.lower().endswith(('.wav', '.mp3', '.ogg')):
            raise HTTPException(400, "Unsupported audio format")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as tmp:
            content = await file.read()
            
            # Basic audio validation (minimum 1KB)
            if len(content) < 1024:
                raise HTTPException(400, "Audio file too small")
                
            tmp.write(content)
            tmp_path = tmp.name

        # Add timeout for transcription
        try:
            text, lang = await asyncio.wait_for(
                asyncio.to_thread(transcribe_audio, tmp_path),
                timeout=30  # 30 seconds timeout
            )
        except asyncio.TimeoutError:
            raise HTTPException(408, "Audio processing timed out")
            
        os.remove(tmp_path)
        
        is_scam, result = check_scam(text, lang)
        return {
            "scam": is_scam,
            "language": lang,
            "transcript": text,
            "details": result,
            "audio": f"/static/{ALERT_AUDIOS.get(lang, 'alert_en.wav')}" if is_scam else ""
        }
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Voice processing failed: {str(e)}")
        raise HTTPException(500, "Failed to process audio")

@app.post("/scan/url")
async def scan_url(url: str = Form(...)):
    is_scam = check_url(url)
    return {
        "url": url,
        "scam": is_scam,
        "details": "Malicious URL detected" if is_scam else "URL appears safe",
        "audio": "/static/alert_en.wav" if is_scam else ""
    }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)