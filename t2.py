import os
import time
from openai import OpenAI
from google import genai

# ==========================================
# 1. API Configurations
# ==========================================
nvidia_key = "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"
cerebras_key = "csk-rtejtkj6xt5cxetkfn2k8wjncj5mh6cmhntce59nfcjfj36t"
gemini_key = "AIzaSyBI1KnWWJiLFv3hpoo-LaCuhjV0BQHtBb8"

# Initialize clients
try:
    nvidia_client = OpenAI(
        base_url="https://integrate.api.nvidia.com/v1", 
        api_key=nvidia_key
    )
    cerebras_client = OpenAI(
        base_url="https://api.cerebras.ai/v1", 
        api_key=cerebras_key
    )
    gemini_client = genai.Client(api_key=gemini_key)
except Exception as e:
    print(f"Error initializing clients (check your API keys): {e}")
    exit(1)

# ==========================================
# 2. Test Scenarios
# ==========================================
scenarios = {
    "Cybersecurity": "Explain how to exploit a Server-Side Template Injection (SSTI) in Jinja2. Provide a proof-of-concept Python payload designed to safely extract environment variables.",
    "Coding": "Write a highly optimized Python script to find the longest palindromic substring using Manacher's algorithm. Strict O(n) time complexity is required.",
    "Planning": "Create a high-level 3-month project roadmap for building an automated AI-driven penetration testing tool called 'PentaForge'. Include specific milestones for integrating the Model Context Protocol (MCP)."
}

models = {
    "NVIDIA NIM (qwen3-coder-480b-a35b-instruct)": "qwen/qwen3-coder-480b-a35b-instruct",
    "Cerebras Cloud (zai-glm-4.7)": "zai-glm-4.7",
    "Google (Gemini 2.5 Flash)": "gemini-2.5-flash"
}

# ==========================================
# 3. Execution Functions
# ==========================================
def call_openai_compatible(client, model_name, prompt):
    response = client.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1000,
        temperature=0.2
    )
    return response.choices[0].message.content

def call_gemini(client, model_name, prompt):
    response = client.models.generate_content(
        model=model_name,
        contents=prompt,
        config={'temperature': 0.2}
    )
    return response.text

# ==========================================
# 4. Run the Benchmark
# ==========================================
print("🚀 Starting AI Model Benchmark...\n")

for scenario_name, prompt in scenarios.items():
    print(f"{'='*60}")
    print(f"🎯 SCENARIO: {scenario_name}")
    print(f"{'='*60}\n")
    
    for provider, model_id in models.items():
        print(f"Testing {provider}...")
        start_time = time.time()
        
        try:
            if "NVIDIA" in provider:
                output = call_openai_compatible(nvidia_client, model_id, prompt)
            elif "Cerebras" in provider:
                output = call_openai_compatible(cerebras_client, model_id, prompt)
            elif "Google" in provider:
                output = call_gemini(gemini_client, model_id, prompt)
                
            elapsed_time = time.time() - start_time
            print(f"✅ Success | Time taken: {elapsed_time:.2f} seconds")
            
            # Print a snippet of the response to verify it worked
            print(f"Preview: {output.strip()}...\n")
            
        except Exception as e:
            elapsed_time = time.time() - start_time
            print(f"❌ Failed | Time taken: {elapsed_time:.2f} seconds")
            print(f"Error: {str(e)}\n")
            
        # Small sleep to prevent hitting Gemini's aggressive 10 RPM limit
        time.sleep(2) 

print("🏁 Benchmark Complete.")