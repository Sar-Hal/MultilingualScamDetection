from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import google.generativeai as genai
import speech_recognition as sr
import pyttsx3
import os
import requests
import re
from googleapiclient.discovery import build

app = FastAPI()

# Configure API keys
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
google_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

# Mount static directory for audio files
app.mount("/static", StaticFiles(directory="."), name="static")

# Input model for content detection
class ContentInput(BaseModel):
    content: str

# Detect scam endpoint
@app.post("/detect")
async def detect_scam(input: ContentInput):
    content = input.content
    is_scam, message = check_scam(content)
    audio = None
    if is_scam:
        audio = generate_audio_alert(message)
    return {"isScam": is_scam, "message": message, "audio": audio}

# Scam detection using Gemini API
def check_scam(content: str) -> tuple:
    # Check for URLs first
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
    for url in urls:
        if check_url(url):
            return True, f"SCAM: Malicious URL detected - {url}"
    
    # Use Gemini for text analysis
    prompt = f"""
    Analyze the following text for potential scam patterns. Look for phrases like 'win a prize', 'urgent action required', or suspicious links. Respond with 'SCAM: <reason>' if a scam is detected, or 'SAFE' if not.

    Text: {content}
    """
    model = genai.GenerativeModel("gemini-1.5-pro")
    response = model.generate_content(prompt)
    result = response.text
    if "SCAM" in result:
        return True, result
    return False, "No scam detected"

# URL checking using Google Safe Browsing API
def check_url(url: str) -> bool:
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

# Transcribe audio using SpeechRecognition with CMU Sphinx
def transcribe_audio(audio_file_path: str) -> str:
    recognizer = sr.Recognizer()
    with sr.AudioFile(audio_file_path) as source:
        audio = recognizer.record(source)
        try:
            # Use CMU Sphinx for offline transcription
            text = recognizer.recognize_sphinx(audio, language="en-US")
            return text
        except sr.UnknownValueError:
            return "Could not understand audio"
        except sr.RequestError as e:
            return f"Error: {e}"

# Generate audio alert using pyttsx3
def generate_audio_alert(message: str) -> str:
    engine = pyttsx3.init()
    audio_path = "alert.mp3"
    engine.save_to_file(message, audio_path)
    engine.runAndWait()
    return f"http://localhost:8000/static/{audio_path}"

# WhatsApp webhook endpoint
@app.post("/webhook")
async def whatsapp_webhook(payload: dict):
    if payload.get("object") == "whatsapp_business_account":
        for entry in payload.get("entry", []):
            for change in entry.get("changes", []):
                value = change.get("value", {})
                if messages := value.get("messages", []):
                    for message in messages:
                        text = message.get("text", {}).get("body", "")
                        audio = message.get("audio", {}).get("id", "")
                        if text:
                            is_scam, scam_message = check_scam(text)
                        elif audio:
                            audio_url = download_whatsapp_audio(audio, os.getenv("WHATSAPP_TOKEN"))
                            transcribed_text = transcribe_audio(audio_url)
                            is_scam, scam_message = check_scam(transcribed_text)
                        else:
                            continue
                        if is_scam:
                            send_whatsapp_response(
                                message["from"], 
                                f"⚠️ Scam Detected: {scam_message}", 
                                os.getenv("WHATSAPP_TOKEN"), 
                                os.getenv("WHATSAPP_PHONE_NUMBER_ID")
                            )
    return {"status": "received"}

# Download WhatsApp audio
def download_whatsapp_audio(audio_id: str, token: str) -> str:
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"https://graph.facebook.com/v13.0/{audio_id}", headers=headers)
    audio_url = response.json().get("url")
    audio_response = requests.get(audio_url, headers=headers)
    with open("temp_audio.wav", "wb") as f:
        f.write(audio_response.content)
    return "temp_audio.wav"

# Send WhatsApp response
def send_whatsapp_response(to: str, message: str, token: str, phone_number_id: str):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": message}
    }
    requests.post(f"https://graph.facebook.com/v13.0/{phone_number_id}/messages", json=payload, headers=headers)

# Test the STT logic
def test_stt():
    audio_file_path = "test_voice.wav"  # Path to your test audio file
    try:
        transcribed_text = transcribe_audio(audio_file_path)
        print("Transcribed text:", transcribed_text)
    except Exception as e:
        print("Error during transcription:", str(e))

if __name__ == "__main__":
    # Run the STT test
    test_stt()
    # Uncomment to run the FastAPI server
    # import uvicorn
    # uvicorn.run(app, host="0.0.0.0", port=8000)
