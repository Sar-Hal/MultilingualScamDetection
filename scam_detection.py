from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import google.generativeai as genai
from langdetect import detect
import requests
import json
import os
import logging
from dotenv import load_dotenv
import nest_asyncio
nest_asyncio.apply()

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

app = FastAPI()

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

def translate_text(text: str, src: str, dest: str) -> str:
    """Mock translation function for testing"""
    return f"[Translated from {src} to {dest}] {text}"

def analyze_text(text: str) -> dict:
    lang = detect(text)
    if lang != 'en':
        text = translate_text(text, src=lang, dest='en')
    
    prompt = f"""
    Analyze this message for scam indicators across these categories:

    **1. Urgency & Fear Tactics**
    - Immediate action required (e.g., "account will be closed within 24h")
    - Threats of legal/financial consequences
    - Emergency financial assistance requests

    **2. Financial Requests**
    - Requests for bank details/passwords
    - Cryptocurrency investment offers
    - Unusual payment methods (gift cards, wire transfers)

    **3. Phishing Patterns**
    - Mismatched sender/receiver context
    - Suspicious links (shortened URLs, misspelled domains)
    - Fake login/verification pages

    **4. Fake Offers**
    - Unexpected prizes/lottery wins
    - "Guaranteed" high-return investments
    - Free products with upfront fees

    **5. Impersonation**
    - False claims from banks/government agencies
    - Fake tech support alerts
    - Romance scams with sudden financial needs

    **6. Language Red Flags** (English/Spanish/French)
    - EN: "Verify your account", "Limited time offer"
    - ES: "Oferta exclusiva", "Cuenta bloqueada"
    - FR: "Virement urgent", "Gagnez un prix"

    **Analysis Rules:**
    1. Detect input language (EN/ES/FR)
    2. Score 0-10 scam likelihood (10=definite scam)
    3. List detected patterns with examples
    4. Consider voice note transcription errors

    **Output Format (JSON):**
    {{
    "risk_level": "Safe/Suspicious/Scam",
    "confidence_score": 0-10,
    "detected_patterns": [
        {{
        "category": "Financial Requests",
        "examples_found": ["Request for Bitcoin wallet address"]
        }}
    ],
    "justification": "Concise explanation in user's language"
    }}

    Message: {text}
    """

    try:
        # Update the generation_config in analyze_text()
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                response_mime_type="application/json",
                response_schema={
                    "type": "object",
                    "properties": {
                        "risk_level": {"type": "string"},
                        "confidence_score": {"type": "number"},
                        "detected_patterns": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "category": {"type": "string"},
                                    "examples_found": {
                                        "type": "array",  # Fixed array definition
                                        "items": {"type": "string"}  # Added item type
                                    }
                                }
                            }
                        },
                        "justification": {"type": "string"}
                    }
                }
            )
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


def transcribe_voice(audio_file_bytes: bytes) -> str:
    try:
        response = model.generate_content(
            contents=[
                {
                    "inline_data": {
                        "mime_type": "audio/webm",
                        "data": base64.b64encode(audio_file_bytes).decode()
                    }
                },
                "Transcribe this audio message"
            ]
        )
        return response.text
    except Exception as e:
        logger.error(f"Transcription failed: {str(e)}")
        raise


@app.post("/scan/text")
async def scan_text(message: str = Form(...)):
    try:
        logger.info(f"Scanning text: {message[:50]}...")
        result = analyze_text(message)
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
        return result
    except Exception as e:
        logger.error(f"Voice scan error: {str(e)}")
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/scan/url")
async def scan_url(url: str = Form(...)):
    try:
        logger.info(f"Scanning URL: {url}")
        api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        payload = {
            "client": {
                "clientId": "your-app-name",
                "clientVersion": "1.0.0"
            },
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
        risk = "Scam" if data.get("matches") else "Safe"
        return {"url": url, "risk": risk, "details": data.get("matches", [])}
        
    except Exception as e:
        logger.error(f"URL scan error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"URL check failed: {str(e)}"}
        )

import uvicorn
import threading

def run_server():
    uvicorn.run(app, host="0.0.0.0", port=8001)

if __name__ == "__main__":
    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    import requests
    response = requests.post(
        "http://localhost:8001/scan/text",
        data={"message": "VERIFY your account http://fake-paypal-login.ru"}
    )
    print("Text scan test:", response.json())
    
    test_url = "https://www.google.com"
    response = requests.post(
        "http://localhost:8001/scan/url",
        data={"url": test_url}
    )
    print("URL scan test:", response.json())
