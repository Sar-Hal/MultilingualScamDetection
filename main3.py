from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import google.generativeai as genai
import os
import requests
import re
from googleapiclient.discovery import build
from faster_whisper import WhisperModel
import tempfile
import logging
from tenacity import retry, stop_after_attempt, wait_fixed
from typing import List, Dict, Any, Tuple
from functools import lru_cache
from dotenv import load_dotenv
from langdetect import detect, LangDetectException

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create static and audio directories with error handling
try:
    os.makedirs("static", exist_ok=True)
    os.makedirs("audio", exist_ok=True)
    logger.info("Created static and audio directories")
except Exception as e:
    logger.error(f"Failed to create directories: {str(e)}")
    raise RuntimeError(f"Cannot create directories: {str(e)}")

# Load environment variables
load_dotenv()

app = FastAPI(
    title="Multilingual Scam Detection API",
    description="Detects scams in text and audio messages in multiple languages",
    version="1.0.0"
)

# Configure API keys
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
google_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

# Audio file paths from environment variables
TEST_AUDIO_PATH = os.getenv("TEST_AUDIO_PATH", r"C:\Users\KIIT0001\Documents\GitHub\MultilingualScamDetection\test_voice.wav")
ALERT_AUDIO_PATH = os.getenv("ALERT_AUDIO_PATH", r"alert.mp3")

# Mount static directory for audio files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Language to alert audio mapping
ALERT_AUDIOS = {
    "en": "alert_en.mp3",
    "fr": "alert_fr.mp3",
    "es": "alert_es.mp3",
    "pt": "alert_pt.mp3",
    "hi": "alert_hi.mp3",
    "de": "alert_de.mp3",
    "it": "alert_it.mp3",
    # Add more languages as needed
}

# Input model for content detection
class ContentInput(BaseModel):
    content: str

# WhatsApp payload model for webhook validation
class WhatsAppMessage(BaseModel):
    text: Dict[str, str] | None = None
    audio: Dict[str, str] | None = None
    from_: str = None

    class Config:
        fields = {"from_": "from"}

class WhatsAppPayload(BaseModel):
    object: str
    entry: List[Dict[str, Any]]

# Detect language of text
def detect_language(text: str) -> str:
    try:
        return detect(text)
    except LangDetectException:
        logger.warning(f"Language detection failed for text: {text[:50]}...")
        return "en"  # Fallback to English

# Detect scam endpoint
@app.post("/detect", summary="Detect scams in text content (multilingual)")
async def detect_scam(input: ContentInput):
    content = input.content
    lang = detect_language(content)
    is_scam, message = check_scam(content, lang)
    audio = None
    if is_scam:
        audio = generate_audio_alert(lang)
    return {"isScam": is_scam, "message": message, "audio": audio, "language": lang}

# Scam detection using Gemini API
@lru_cache(maxsize=1000)
def check_scam(content: str, lang: str) -> tuple:
    # Sanitize input
    content = content.strip()
    if not content:
        return False, "Empty content provided"

    # Check for URLs first
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
    for url in urls:
        if check_url(url):
            return True, f"SCAM: Malicious URL detected - {url}"
    
    # Multilingual scam patterns
    scam_phrases = {
        "en": ["win a prize", "urgent action required", "verify your account"],
        "fr": ["gagnez un prix", "action urgente requise", "vérifiez votre compte"],
        "es": ["gana un premio", "acción urgente requerida", "verifica tu cuenta"],
        "pt": ["ganhe um prêmio", "ação urgente necessária", "verifique sua conta"],
        "hi": ["पुरस्कार जीतें", "तत्काल कार्रवाई आवश्यक", "अपना खाता सत्यापित करें"],
        "de": ["gewinnen Sie einen Preis", "dringende Maßnahmen erforderlich", "überprüfen Sie Ihr Konto"],
        "it": ["vinci un premio", "azione urgente richiesta", "verifica il tuo account"],
    }
    lang_phrases = scam_phrases.get(lang, scam_phrases["en"])  # Fallback to English

    # Use Gemini for text analysis
    prompt = f"""
    Analyze the following text for potential scam patterns in {lang} language. Look for phrases like {', '.join(f'"{p}"' for p in lang_phrases)} or suspicious links. Respond with 'SCAM: <reason>' if a scam is detected, or 'SAFE' if not.

    Text: {content}
    """
    try:
        model = genai.GenerativeModel("gemini-1.5-pro")
        response = model.generate_content(prompt)
        result = response.text
        if "SCAM" in result:
            return True, result
        return False, "No scam detected"
    except Exception as e:
        logger.error(f"Gemini API error: {str(e)}")
        return False, f"Error analyzing content: {str(e)}"

# URL checking using Google Safe Browsing API
@lru_cache(maxsize=1000)
def check_url(url: str) -> bool:
    try:
        service = build("safebrowsing", "v4", developerKey=google_api_key)
        threats = service.threatMatches().find(body={
            "client": {"clientId": "yourcompany", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }).execute()
        return bool(threats.get("matches"))
    except Exception as e:
        logger.error(f"Safe Browsing API error for URL {url}: {str(e)}")
        return False

# Transcribe audio using faster-whisper (multilingual)
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def transcribe_audio(audio_file_path: str) -> Tuple[str, str]:
    if not os.path.exists(audio_file_path):
        logger.error(f"Audio file not found: {audio_file_path}")
        return "Error: Audio file not found", "en"
    if os.path.getsize(audio_file_path) == 0:
        logger.error(f"Audio file is empty: {audio_file_path}")
        return "Error: Audio file is empty", "en"

    try:
        # Transcribe with faster-whisper
        logger.info(f"Transcribing audio: {audio_file_path}")
        model = WhisperModel("base", device="cpu")
        segments, info = model.transcribe(audio_file_path, beam_size=5, language=None)  # Auto-detect language
        text = " ".join(segment.text for segment in segments)
        detected_lang = info.language if info.language else "en"
        logger.info(f"Transcription result: {text} (language: {detected_lang})")
        return text or "No speech detected", detected_lang
    except Exception as e:
        logger.error(f"Transcription failed for {audio_file_path}: {str(e)}")
        return f"Transcription error: {str(e)}", "en"

# Generate audio alert using pre-existing MP3
def generate_audio_alert(lang: str) -> str:
    try:
        # Select alert audio based on language
        alert_file = ALERT_AUDIOS.get(lang, ALERT_AUDIO_PATH)
        alert_path = os.path.join("static", os.path.basename(alert_file))
        
        # Validate alert file
        if not os.path.exists(alert_path):
            logger.error(f"Alert audio file not found: {alert_path}")
            return ""
        if os.path.getsize(alert_path) == 0:
            logger.error(f"Alert audio file is empty: {alert_path}")
            return ""
        
        audio_url = f"http://localhost:8000/static/{os.path.basename(alert_file)}"
        logger.info(f"Using pre-existing audio alert: {audio_url} (language: {lang})")
        return audio_url
    except Exception as e:
        logger.error(f"Audio alert generation failed: {str(e)}")
        return ""

# WhatsApp webhook endpoint
@app.post("/webhook", summary="Process WhatsApp webhook events (multilingual)")
async def whatsapp_webhook(payload: WhatsAppPayload):
    if payload.object != "whatsapp_business_account":
        return {"status": "invalid payload"}

    try:
        for entry in payload.entry:
            for change in entry.get("changes", []):
                value = change.get("value", {})
                if messages := value.get("messages", []):
                    for message in messages:
                        msg = WhatsAppMessage(**message)
                        if msg.text:
                            text = msg.text.get("body", "")
                            lang = detect_language(text)
                            is_scam, scam_message = check_scam(text, lang)
                        elif msg.audio:
                            audio_path = download_whatsapp_audio(msg.audio.get("id", ""), os.getenv("WHATSAPP_TOKEN"))
                            transcribed_text, lang = transcribe_audio(audio_path)
                            is_scam, scam_message = check_scam(transcribed_text, lang)
                            # Clean up temporary audio file
                            if os.path.exists(audio_path):
                                os.remove(audio_path)
                        else:
                            continue
                        if is_scam:
                            send_whatsapp_response(
                                msg.from_, 
                                f"⚠️ Scam Detected: {scam_message}", 
                                os.getenv("WHATSAPP_TOKEN"), 
                                os.getenv("WHATSAPP_PHONE_NUMBER_ID")
                            )
                            generate_audio_alert(lang)
        return {"status": "received"}
    except Exception as e:
        logger.error(f"Webhook processing error: {str(e)}")
        return {"status": "error", "message": str(e)}

# Download WhatsApp audio
def download_whatsapp_audio(audio_id: str, token: str) -> str:
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"https://graph.facebook.com/v13.0/{audio_id}", headers=headers)
        response.raise_for_status()
        audio_url = response.json().get("url")
        audio_response = requests.get(audio_url, headers=headers)
        audio_response.raise_for_status()

        # Save audio to temporary file
        temp_path = tempfile.NamedTemporaryFile(suffix=".opus", delete=False).name
        with open(temp_path, "wb") as f:
            f.write(audio_response.content)
        return temp_path
    except Exception as e:
        logger.error(f"Failed to download WhatsApp audio {audio_id}: {str(e)}")
        raise Exception(f"Audio download error: {str(e)}")

# Send WhatsApp response
def send_whatsapp_response(to: str, message: str, token: str, phone_number_id: str):
    try:
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {
            "messaging_product": "whatsapp",
            "to": to,
            "type": "text",
            "text": {"body": message}
        }
        response = requests.post(
            f"https://graph.facebook.com/v13.0/{phone_number_id}/messages",
            json=payload,
            headers=headers
        )
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Failed to send WhatsApp response to {to}: {str(e)}")

# Test the STT logic
def test_stt(audio_file_path: str = TEST_AUDIO_PATH):
    try:
        # Validate test audio file
        if not os.path.exists(audio_file_path):
            raise FileNotFoundError(f"Test audio file not found: {audio_file_path}")
        if os.path.getsize(audio_file_path) == 0:
            raise ValueError(f"Test audio file is empty: {audio_file_path}")
        
        transcribed_text, lang = transcribe_audio(audio_file_path)
        print(f"Transcribed text: {transcribed_text} (language: {lang})")
    except Exception as e:
        print("Error during transcription:", str(e))

if __name__ == "__main__":
    # Run the STT test with the configured audio file
    test_stt()
    # Uncomment to run the FastAPI server
    # import uvicorn
    # uvicorn.run(app, host="0.0.0.0", port=8000)