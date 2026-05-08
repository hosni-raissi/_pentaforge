import os
import time
from openai import OpenAI

# ==========================================
# 1. API Configurations
# ==========================================
nvidia_key = "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"
mistral_key = "7JWrPGqRzcnY6ApEXdGX9D52PqASthwt"
mistral_model = "mistral-large-latest"
mistral_url = "https://api.mistral.ai/v1"

if not nvidia_key or not mistral_key:
    print("Error: Please set NVIDIA_API_KEY and MISTRAL_API_KEY environment variables.")
    exit(1)

# Initialize NVIDIA Client (Qwen 3 Coder)
nvidia_client = OpenAI(
    base_url="https://integrate.api.nvidia.com/v1",
    api_key=nvidia_key
)

# Initialize Mistral Client using your PentaForge architecture variables
mistral_client = OpenAI(
    base_url=mistral_url,
    api_key=mistral_key
)

# ==========================================
# 2. Exploit Agent Scenario
# ==========================================
# A realistic prompt an Exploit Agent might process in PentaForge
exploit_prompt = """
Role: You are the Lead Penetration Tester and AI Orchestrator for 'PentaForge'. 
Task: Generate a comprehensive, stealth-focused penetration testing plan for a target web application located at 'https://target-app.internal'.

The plan must be structured for an automated agent execution and include the following phases:

1. Passive Reconnaissance: Define how to identify the tech stack (WAF, CMS, Web Server) and search for leaked credentials or subdomains without touching the target server directly.
2. Active Discovery: List specific CLI tools (e.g., ffuf, nmap, nuclei) and the exact flags required to perform directory discovery and port scanning while bypassing a standard WAF (include jitter and custom headers).
3. Targeted Vulnerability Analysis: Based on the tech stack (assume React frontend / Node.js backend), prioritize the top 3 OWASP vulnerabilities to test. Detail the logic for testing 'Broken Access Control' and 'Insecure Direct Object References (IDOR)'.
4. Exploitation Path: Describe a logic chain to escalate a 'Low' severity Information Disclosure finding into a 'High' severity Account Takeover.
5. Reporting & Remediation: Provide a JSON-formatted summary of these steps that includes 'Command', 'Expected_Output', and 'Risk_Level'.

Constraint: Output only the structured plan and the JSON summary. Do not provide conversational filler or introductory text.
"""

# ==========================================
# 3. Execution Function
# ==========================================
def run_exploit_agent(client, model_name, provider):
    print(f"[{provider}] Initializing Exploit Agent -> Model: {model_name}...")
    start_time = time.time()
    
    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": "You are a senior Red Team operator and exploit developer."},
                {"role": "user", "content": exploit_prompt}
            ],
            temperature=0.2,
            max_tokens=1500
        )
        output = response.choices[0].message.content
        elapsed_time = time.time() - start_time
        
        print(f"✅ Success | Time taken: {elapsed_time:.2f} seconds")
        print(f"Preview of Exploit Code:\n{output.strip()}...\n")
        print("-" * 60)
        
    except Exception as e:
        elapsed_time = time.time() - start_time
        print(f"❌ Failed | Time taken: {elapsed_time:.2f} seconds")
        print(f"Error: {str(e)}\n")
        print("-" * 60)

# ==========================================
# 4. Run the Benchmark
# ==========================================
print("🚀 Starting PentaForge Exploit Agent Benchmark...\n")
print("-" * 60)

# Test NVIDIA (Qwen 3 Coder)
run_exploit_agent(
    client=nvidia_client, 
    model_name="stepfun-ai/step-3.5-flash", 
    provider="NVIDIA NIM"
)

# Test Mistral (Mistral Large)
run_exploit_agent(
    client=mistral_client, 
    model_name=mistral_model, 
    provider="Mistral AI"
)

print("🏁 Benchmark Complete.")