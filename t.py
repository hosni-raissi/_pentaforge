import os
import time
from openai import OpenAI
from google import genai

# ==========================================
# 1. API Configurations
# ==========================================
# SECURE PRACTICE: export MISTRAL_API_KEY="your_key" in terminal
mistral_key = "7JWrPGqRzcnY6ApEXdGX9D52PqASthwt"
gemini_key = "AIzaSyA5ryrfQxHDvsfBrlrPWAf5nHIXD9GVU2s"
 #"AIzaSyBI1KnWWJiLFv3hpoo-LaCuhjV0BQHtBb8"

mistral_model = "mistral-large-latest"
gemini_model = "gemini-2.5-flash"

# Initialize clients
try:
    mistral_client = OpenAI(
        base_url="https://api.mistral.ai/v1",
        api_key=mistral_key
    )
    gemini_client = genai.Client(api_key=gemini_key)
except Exception as e:
    print(f"❌ Initialization Error: {e}")
    exit(1)

# ==========================================
# 2. Test Scenarios
# ==========================================
scenarios = {
    "Cybersecurity": "Explain how to exploit a Server-Side Template Injection (SSTI) in Jinja2. Provide a proof-of-concept Python payload designed to safely extract environment variables.",
    "Coding": "Write a highly optimized Python script to find the longest palindromic substring using Manacher's algorithm. Strict $O(n)$ time complexity is required.",
    "Planning": "Create a high-level 3-month project roadmap for building 'PentaForge'. Include specific milestones for integrating the Model Context Protocol (MCP)."
}

# ==========================================
# 3. Execution Functions
# ==========================================
def call_mistral(prompt):
    response = mistral_client.chat.completions.create(
        model=mistral_model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2
    )
    return response.choices[0].message.content

def call_gemini_lite(prompt):
    # Retries for the common 503 Service Unavailable errors
    for i in range(3):
        try:
            response = gemini_client.models.generate_content(
                model=gemini_model,
                contents=prompt,
                config={'temperature': 0.2}
            )
            return response.text
        except Exception as e:
            if "503" in str(e) and i < 2:
                time.sleep(3)
                continue
            raise e

# ==========================================
# 4. Run the Benchmark
# ==========================================
print(f"🚀 Benchmarking: {mistral_model} vs {gemini_model}\n")

for name, prompt in scenarios.items():
    print(f"{'='*60}\n🎯 SCENARIO: {name}\n{'='*60}")
    
    for provider in ["Mistral Large 3", "Gemini 2.5 Flash-Lite"]:
        print(f"Testing {provider}...")
        start = time.time()
        try:
            output = call_mistral(prompt) if "Mistral" in provider else call_gemini_lite(prompt)
            duration = time.time() - start
            print(f"✅ {provider} Success | Time: {duration:.2f}s")
            print(f"Preview: {output.strip()}...\n")
        except Exception as e:
            print(f"❌ {provider} Failed | Error: {str(e)}\n")
        
        time.sleep(2) # Avoid hitting rate limits too fast

print("🏁 Benchmark Complete.")