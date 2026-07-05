import os
from dotenv import load_dotenv
import google.generativeai as genai

# Load variables from .env
load_dotenv()

# Read the API key
api_key = os.getenv("GEMINI_API_KEY")

# Configure Gemini
genai.configure(api_key=api_key)