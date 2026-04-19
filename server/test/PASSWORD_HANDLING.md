# Interactive Password Handling System

## Overview

When tools like `ssh`, `sudo`, or database clients need passwords, the system now supports interactive password input through the frontend instead of silently failing.

## Flow Diagram

```
┌─────────────────┐
│  Tool Execution │
│  (ssh/sudo)     │
└────────┬────────┘
         │ Needs password
         ↓
┌─────────────────────────────────┐
│  Tool detects password prompt   │
│  Calls: callback.request_password(
│    prompt="SSH password: ",
│    reason="Connect to scanme.nmap.org",
│    call_id="abc123"
│  )
└────────┬────────────────────────┘
         │
         ↓
┌──────────────────────────────────┐
│  ORCHESTRATOR EVENT EMITTED      │
│  executer_password_request       │
│                                  │
│  {                               │
│    "stage": "executor",          │
│    "kind": "password_request",   │
│    "tool_name": "ssh",           │
│    "prompt": "SSH password: ",   │
│    "reason": "Connect to...",    │
│    "call_id": "abc123"           │
│  }                               │
└────────┬───────────────────────┘
         │
         ↓ (Event sent to Frontend)
┌──────────────────────────────────┐
│  FRONTEND DISPLAYS PASSWORD      │
│  DIALOG                          │
│                                  │
│  🔒 SSH Password Required        │
│                                  │
│  Reason: Connect to ...          │
│  Prompt: SSH password: _______   │
│                                  │
│  [ALLOW - PASSWORD] [DENY]       │
└────────┬───────────────────────┘
         │
         ↓ (User interaction)
    User enters password OR clicks DENY
         │
         ↓ (Response sent back)
┌──────────────────────────────────┐
│  ORCHESTRATOR receives response  │
│  /api/executor/password-response │
│                                  │
│  {                               │
│    "call_id": "abc123",          │
│    "approved": true/false,       │
│    "password": "secret123"       │
│  }                               │
└────────┬───────────────────────┘
         │
         ↓
┌──────────────────────────────────┐
│  PASSWORD STORED IN EXECUTOR     │
│  CALLBACK (in-memory, encrypted) │
│                                  │
│  password_cache[call_id] =       │
│    "secret123"                   │
└────────┬───────────────────────┘
         │
         ↓
┌──────────────────────────────────┐
│  TOOL RETRIEVES PASSWORD FROM    │
│  CALLBACK                        │
│                                  │
│  password = callback.get_password(
│    call_id="abc123"
│  )                               │
└────────┬───────────────────────┘
         │
         ↓ (passes password to subprocess)
┌──────────────────────────────────┐
│  SUBPROCESS EXECUTION            │
│  $ ssh -v scanme.nmap.org        │
│  (reads password from stdin/     │
│   expect script)                 │
└────────┬───────────────────────┘
         │
         ↓
┌──────────────────────────────────┐
│ RESULT RETURNED TO AGENT         │
│ (password NOT logged or stored)  │
└──────────────────────────────────┘
```

## Implementation Details

### 1. Callback Protocol Addition

**File**: `server/agents/executer/base.py`

```python
class ExecuterCallback(Protocol):
    def request_password(
        self,
        *,
        prompt: str,          # "SSH password: " or "sudo password: "
        reason: str,          # "Connect to scanme.nmap.org"
        call_id: str,         # Unique identifier for this request
    ) -> str | None:         # Returns password or None if denied
        ...
```

### 2. Orchestrator Event Emission

**File**: `server/app/orchestrator.py` (planned)

When a tool needs a password, the orchestrator emits:

```python
self._emit_event(
    project_id,
    event="executer_password_request",
    scan_id=scan_id,
    level="info",
    message=f"[{tool_name}] Password required: {prompt}",
    data={
        "stage": "executor",
        "kind": "password_request",
        "tool_name": "ssh",
        "prompt": "SSH password: ",
        "reason": "Connect to scanme.nmap.org",
        "call_id": call_id,    # Frontend uses this in response
    },
)
```

### 3. Frontend API Endpoint

**Endpoint**: `POST /api/executor/password-response`

Frontend sends back:
```json
{
  "scan_id": "scan-uuid",
  "call_id": "abc123",
  "approved": true,
  "password": "user_entered_password_here"
}
```

Or if denied:
```json
{
  "scan_id": "scan-uuid",
  "call_id": "abc123",
  "approved": false,
  "password": null
}
```

### 4. Tool Integration (run_custom example)

**File**: `server/agents/executer/exploit/tools/all/run_custom.py` (planned)

```python
def _execute_with_password_support(command, args, callback, call_id):
    """Execute command with password support if needed."""

    # Build command
    full_cmd = build_command(command, args)

    # Check if this command typically needs a password
    needs_password = _command_needs_password(command)

    if needs_password:
        # Request password from callback
        password = callback.request_password(
            prompt=f"{command} password: ",
            reason=f"Execute: {' '.join(args[:3])}...",
            call_id=call_id,
        )

        if password is None:
            # User denied password, skip execution
            return {
                "status": "skipped",
                "reason": "Password required but not provided by user",
                "output": "",
            }

        # Execute with password via stdin or expect
        result = _run_with_stdin(full_cmd, stdin=password)
    else:
        # Execute normally (no password needed)
        result = subprocess.run(full_cmd, ...)

    return result
```

### 5. Command Password Detection

Commands that typically need passwords:
- `ssh` - SSH password authentication
- `ssh-keyscan` - May need host verification
- `sudo` - Privilege elevation
- `mysql -p` - Database password
- `psql --password` - PostgreSQL password
- `sqlite3` - Database access
- `ftp` - FTP login

### 6. Security Considerations

✅ **What's Protected**:
- Passwords are **NOT logged** anywhere
- Passwords are **NOT saved** to files
- Passwords are **NOT included** in tool_results returned to LLM
- Passwords are **cleared from memory** after tool execution
- Passwords are **transmitted over HTTPS only** (frontend → orchestrator)

✅ **Secure Storage**:
```python
# In-memory cache, cleared after use
password_cache: dict[str, str] = {}

# Usage:
password_cache[call_id] = encrypted_password  # During password request

# Tool uses it:
password = password_cache.get(call_id)

# Immediate cleanup:
del password_cache[call_id]  # After tool execution
```

## Usage Examples

### Example 1: SSH Connection

**User's request**:
```
Test SSH authentication on scanme.nmap.org
```

**Execution Flow**:
1. Exploit agent creates: `ssh -v scanme.nmap.org`
2. Tool detects SSH will prompt for password
3. **Event sent**: `executer_password_request` → Frontend
4. **Frontend shows**: "🔒 SSH Password Required - Connect to scanme.nmap.org"
5. **User enters**: password
6. **Tool receives**: password via stdin
7. **Result**: SSH connection attempted
8. **Output**: SSH banner, key info, authentication methods

### Example 2: Sudo Privilege Escalation

**User's request**:
```
Run privileged network scan with sudo
```

**Execution Flow**:
1. Exploit agent creates: `sudo nmap -sV target`
2. Tool detects sudo will prompt for password
3. **Event sent**: `executer_password_request` → Frontend
4. **Frontend shows**: "🔒 Sudo Password Required - Run privileged scan"
5. **User enters**: sudo password
6. **Tool receives**: password via stdin
7. **Result**: Privileged nmap scan executes
8. **Output**: Full version detection with elevated privileges

### Example 3: User Denies Password

**Execution Flow**:
1. Tool needs password
2. **Event sent**: `executer_password_request` → Frontend
3. **Frontend shows**: Password dialog
4. **User clicks**: [DENY]
5. **Tool status**: `"skipped"` with reason "Password not provided"
6. **Next agent round**: Agent sees "skipped" result, tries alternative approach

## Frontend UI Implementation

### Password Request Dialog

```
┌─────────────────────────────────────┐
│ 🔒 Password Required                │
├─────────────────────────────────────┤
│                                     │
│ Tool: ssh                           │
│ Reason: Connect to scanme.nmap.org  │
│ Prompt: SSH password:               │
│                                     │
│ Password: [***________] (input)     │
│                                     │
│        [ALLOW]  [DENY]              │
│                                     │
└─────────────────────────────────────┘
```

**Fields**:
- Tool name (what's requesting)
- Reason (why it needs password)
- Prompt (exact password prompt from tool)
- Input field (user enters password)
- ALLOW/DENY buttons

## Event Stream Example

```
Scan started for scanme.nmap.org

[EXECUTOR] Exploit agent starting round 1/3
[EXECUTOR] LLM selected: ssh -v scanme.nmap.org

🔒 [PASSWORD REQUIRED] SSH authentication to scanme.nmap.org
  - Tool: ssh
  - Reason: Test SSH authentication
  - Prompt: "SSH password:"
  [USER ACTION REQUIRED - WAITING FOR PASSWORD]

User approved and entered password...

[EXECUTOR] Tool execution: ssh -v scanme.nmap.org
[EXECUTOR] Tool completed (SSH connection successful)

[EXECUTOR] Exploit agent LLM round 2/3
...
```

## Status

**Current**:
- ✅ Callback protocol updated with `request_password()` method
- ✅ _NoOpCallback implementation (returns None by default)
- ✅ Base framework in place

**Next Steps**:
- 🔄 Orchestrator event emission for password requests
- 🔄 API endpoint for password responses
- 🔄 Frontend UI dialog implementation
- 🔄 run_custom tool integration
- 🔄 Password cache management and cleanup
- 🔄 Encryption for in-memory storage
- 🔄 Security audit and testing
