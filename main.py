from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import google.generativeai as genai
import os


app = FastAPI()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

class ContentInput(BaseModel):
    content: str

@app.post("/detect")
async def detect_scam(input: ContentInput):
    content = input.content
    # Placeholder for scam detection (implemented later)
    is_scam, message = check_scam(content)
    audio = None
    if is_scam:
        # Placeholder for TTS (implemented later)
        audio = generate_audio_alert(message)
    return {"isScam": is_scam, "message": message, "audio": audio}

def check_scam(content: str) -> tuple:
   prompt = f"""
    Analyze the following text for potential scam patterns. Look for phrases like 'win a prize', 'urgent action required', or suspicious links. Respond with 'SCAM: <reason>' if a scam is detected, or 'SAFE' if not.

    Text: {content}
    """
   model = genai.GenerativeModel("gemini-1.5-pro")  # Use the appropriate Gemini model
   response = model.generate_content(prompt)
   result = response.text
   if "SCAM" in result:
        return True, result
   return False, "No scam detected"

def generate_audio_alert(message: str) -> str:
    # Placeholder: Will integrate TTS
    return None

@app.post("/webhook")
async def whatsapp_webhook(payload: dict):
    # Placeholder for WhatsApp webhook (implemented later)
    return {"status": "received"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)