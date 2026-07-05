import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

model = genai.GenerativeModel("gemini-2.5-flash")


def explain_threat(destination_port, flow_duration, prediction, risk):
    prompt = f"""
You are an expert SOC Analyst.

Analyze this network traffic.

Destination Port : {destination_port}
Flow Duration : {flow_duration}
Prediction : {prediction}
Risk : {risk}

Provide:

1. Threat Summary
2. Why it is suspicious
3. Risk Level
4. Recommended Action

Keep the answer under 150 words.
"""

    response = model.generate_content(prompt)

    return response.text