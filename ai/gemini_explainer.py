import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

model = genai.GenerativeModel("gemini-2.5-flash")


def explain_threat(
        destination_port,
        flow_duration,
        prediction,
        risk,
        tactic,
        technique,
        technique_id,
        description,
        mitigation):

    prompt = f"""
You are an expert Security Operations Center (SOC) Analyst.

Analyze the following suspicious network traffic.

==========================
Network Information
==========================

Destination Port : {destination_port}
Flow Duration : {flow_duration}

Attack Type : {prediction}

Risk Level : {risk}

==========================
MITRE ATT&CK Mapping
==========================

Tactic : {tactic}

Technique : {technique}

Technique ID : {technique_id}

Description :

{description}

Recommended Mitigation :

{mitigation}

==========================

Provide:

1. Threat Summary

2. Why this attack is dangerous

3. Explain the MITRE ATT&CK technique

4. Indicators of Compromise (IoCs)

5. Recommended actions for the SOC analyst

6. Business impact

Keep the answer under 200 words.
"""

    response = model.generate_content(prompt)

    return response.text