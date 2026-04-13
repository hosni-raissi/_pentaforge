# crAPI Setup Guide for PentaForge API Tool Testing

## Quick Start

### Option 1: Docker (Recommended)
```bash
# Pull and run crAPI
docker pull amlwwalker/crapi
docker run -d --name crapi -p 8888:8888 amlwwalker/crapi

# Verify it's running
curl http://127.0.0.1:8888/api/v1/home
```

### Option 2: Git Clone & Run
```bash
# Clone crAPI repository
git clone https://github.com/amlwwalker/crapi.git
cd crapi

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
# Listen on http://127.0.0.1:8888
```

### Option 3: From Source (Python)
```bash
# If you have Python 3.8+
git clone https://github.com/amlwwalker/crapi.git
cd crapi
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
```

## Verify Installation

```bash
# Test endpoint discovery
curl -s http://127.0.0.1:8888/api/v1/home | jq .

# Expected response
{
  "message": "Welcome to crAPI"
}

# List available endpoints
curl -s http://127.0.0.1:8888/api/v1/ | jq .
```

## crAPI Vulnerable Features

- **BOLA (Broken Object Level Authorization)**: Update other users' profiles
- **Broken Authentication**: Weak password requirements, JWT issues
- **Information Disclosure**: Leaky endpoints expose internal data
- **Injection Vulnerabilities**: SQL/NoSQL injection points
- **Sensitive Data Exposure**: API keys, tokens in responses
- **Rate Limiting Bypass**: No rate limit on sensitive operations
- **Mass Assignment**: Extra fields in JSON accepted
- **Business Logic Flaws**: State manipulation vulnerabilities

## Test Commands with PentaForge API Tools

### 1. Endpoint Discovery
```bash
python -m server.agents.executer.recon.tools.api.api_endpoint_discovery -t "http://127.0.0.1:8888" --method "crawl"
```

### 2. Parameter Discovery
```bash
python -m server.agents.executer.recon.tools.web.param_discovery -t "http://127.0.0.1:8888/api/v1" --method "fuzz"
```

### 3. GraphQL Reconnaissance
```bash
python -m server.agents.executer.recon.tools.api.graphql_recon -t "http://127.0.0.1:8888/graphql"
```

### 4. OAuth/OIDC Check
```bash
python -m server.agents.executer.recon.tools.api.oauth_oidc_check -t "http://127.0.0.1:8888"
```

### 5. API Fuzzing
```bash
python -m server.agents.executer.recon.tools.api.api_fuzzing -t "http://127.0.0.1:8888/api/v1" --tool "ffuf"
```

### 6. API Authentication Testing
```bash
python -m server.agents.executer.recon.tools.api.api_auth_test -t "http://127.0.0.1:8888" --auth-type "jwt"
```

## Environment Configuration

```bash
# Allow localhost testing
export PENTAFORGE_ALLOW_LOCAL_API_TARGETS=true
export PENTAFORGE_ALLOW_LOCAL_TARGETS=true

# Set test API URL
export TEST_API_TARGET="http://127.0.0.1:8888"
```

## Known crAPI Endpoints

```
GET  /api/v1/home
GET  /api/v1/user/profile
POST /api/v1/user/login
POST /api/v1/user/register
POST /api/v1/user/refresh
GET  /api/v1/vehicle/{id}
POST /api/v1/vehicle/add
GET  /api/v1/vehicle/list
GET  /api/v1/community/posts
POST /api/v1/community/posts
```

## Troubleshooting

### Port Already in Use
```bash
# Find and kill process on 8888
lsof -i :8888
kill -9 <PID>
```

### Connection Refused
```bash
# Check if container is running
docker ps | grep crapi

# Check logs
docker logs crapi

# Restart container
docker restart crapi
```

### Slow Response Times
- crAPI may be sluggish on first load
- Wait 10-15 seconds after starting
- Check Docker memory allocation

## Sample Test Script

```bash
#!/bin/bash
set -e

API_TARGET="http://127.0.0.1:8888"

echo "🔍 Testing PentaForge API Tools against crAPI"
echo "=============================================="

# Require local targets
export PENTAFORGE_ALLOW_LOCAL_API_TARGETS=true

echo "✓ Endpoint Discovery..."
python -m server.agents.executer.recon.tools.api.api_endpoint_discovery \
  --target "$API_TARGET" 2>/dev/null | head -20

echo ""
echo "✓ Parameter Discovery..."
python -m server.agents.executer.recon.tools.web.param_discovery \
  --target "$API_TARGET/api/v1" 2>/dev/null | head -20

echo ""
echo "✓ OAuth/OIDC Check..."
python -m server.agents.executer.recon.tools.api.oauth_oidc_check \
  --target "$API_TARGET" 2>/dev/null || echo "No OAuth endpoint (expected)"

echo ""
echo "✓ All tests complete!"
```

Save as `test_crapi.sh` and run:
```bash
chmod +x test_crapi.sh
./test_crapi.sh
```
