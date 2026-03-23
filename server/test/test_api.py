import requests

url = "https://api.hyperbolic.xyz/v1/chat/completions"
payload = {
    "model": "meta-llama/llama-3.1-405b-instruct",
    "messages": [
        {"role": "user", "content": "YOUR 500,000 TOKEN PROMPT HERE IT WILL READ EVERYTHING"}
    ],
    "temperature": 0.7,
    "max_tokens": 4000
}

headers = {"Content-Type": "application/json"}
response = requests.post(url, json=payload, headers=headers)
print(response.json())