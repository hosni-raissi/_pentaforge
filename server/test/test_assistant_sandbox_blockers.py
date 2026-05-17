from __future__ import annotations

from server.agents.assistant.agent import AssistantAgent
from server.agents.assistant.prompts import SYSTEM_PROMPT
from server.agents.assistant.security_tools import (
    ASSISTANT_ALLOWED_NETWORK_COMMANDS,
    ASSISTANT_AVAILABLE_SECURITY_TOOLS,
    ASSISTANT_SANDBOX_RUN_CUSTOM_CATALOG,
    ASSISTANT_SANDBOX_WORDLISTS,
    ASSISTANT_TARGET_OPTIONAL_COMMANDS,
)


def test_assistant_repairs_sandbox_blocker_reply_into_environment_next_step() -> None:
    repaired = AssistantAgent._ensure_structured_reply(
        """Summary:
The attempt to fetch the target body failed due to an unavailable sandbox executor.

Verdict:
needs_retest

Evidence:
- Tool Execution Failure: curl failed because the sandbox executor was unavailable.

Unknowns:
- The content of the target body is still unknown.

Next Step:
- get_page(url='http://scanme.nmap.org') - Attempt to fetch the page content using the get_page tool as an alternative.

Confidence:
High
""",
        tool_results=[
            {
                "success": False,
                "command": "curl",
                "full_command": "curl http://scanme.nmap.org",
                "error": "Sandbox executor unavailable: run_custom may only execute through the tool sandbox. Configure SANDBOX_EXECUTOR_URL for backend-side callers.",
            }
        ],
        prompt="curl http://scanme.nmap.org",
        target="http://scanme.nmap.org",
    )

    assert "tool sandbox" in repaired.lower()
    assert "SANDBOX_EXECUTOR_URL" in repaired
    assert "get_page(url='http://scanme.nmap.org')" not in repaired


def test_assistant_prompt_includes_real_sandbox_security_tools() -> None:
    assert "Available sandbox security tools:" in SYSTEM_PROMPT
    assert "Sandbox wordlist catalog" in SYSTEM_PROMPT
    assert "Sandbox run_custom starter catalog" in SYSTEM_PROMPT
    assert "Never invent wordlist filenames or paths." in SYSTEM_PROMPT
    assert "Do not rewrite `301` or `302` as `200`" in SYSTEM_PROMPT
    assert "For `ffuf`, add `-ic`" in SYSTEM_PROMPT
    assert "`wafw00f`" in SYSTEM_PROMPT
    assert "`wappalyzer`" in SYSTEM_PROMPT
    assert "`docker`" in SYSTEM_PROMPT
    assert "wordlists/short.txt" in SYSTEM_PROMPT
    assert "../share/wordlists/short.txt" not in SYSTEM_PROMPT
    assert ASSISTANT_SANDBOX_WORDLISTS["short"]["p"] == "wordlists/short.txt"
    assert ASSISTANT_SANDBOX_RUN_CUSTOM_CATALOG["ffuf"]["u"] == (
        "ffuf -u http://TARGET/FUZZ -w wordlists/short.txt -ic -mc all -fc 404"
    )
    assert "wafw00f" in ASSISTANT_AVAILABLE_SECURITY_TOOLS
    assert "wappalyzer" in ASSISTANT_ALLOWED_NETWORK_COMMANDS
    assert "docker" in ASSISTANT_ALLOWED_NETWORK_COMMANDS
    assert "docker" in ASSISTANT_TARGET_OPTIONAL_COMMANDS
    assert "ls" in ASSISTANT_TARGET_OPTIONAL_COMMANDS


def test_assistant_normalizes_legacy_sandbox_wordlist_paths() -> None:
    assert AssistantAgent._normalize_run_custom_command("fuf") == "ffuf"
    assert AssistantAgent._prompt_is_direct_run_custom_request(
        "ffuf -u http://scanme.nmap.org/FUZZ -w wordlists/short.txt -ic -mc all -fc 404"
    ) is True

    normalized = AssistantAgent._normalize_run_custom_args(
        "ffuf",
        [
            "-u",
            "http://scanme.nmap.org/FUZZ",
            "-w",
            "../share/wordlists/short.txt",
            "-mc",
            "200,301,302,403",
        ],
    )

    assert normalized == [
        "-u",
        "http://scanme.nmap.org/FUZZ",
        "-w",
        "wordlists/short.txt",
        "-mc",
        "200,301,302,403",
    ]


def test_assistant_infers_ffuf_thread_limit_failure_cause() -> None:
    cause = AssistantAgent._infer_command_failure_cause(
        "ffuf",
        [
            "-u",
            "http://scanme.nmap.org/FUZZ",
            "-w",
            "wordlists/short.txt",
        ],
        {
            "return_code": 2,
            "stderr": "runtime/cgo: pthread_create failed: Resource temporarily unavailable",
        },
    )

    assert "sandbox resource limit" in cause.lower()


def test_assistant_repairs_incorrect_ffuf_no_match_summary() -> None:
    repaired = AssistantAgent._ensure_structured_reply(
        """Summary:
Ran a lightweight content discovery scan using ffuf to identify hidden files on http://scanme.nmap.org. No hidden files or directories were discovered in this initial pass.
Verdict: observed
Confidence: Medium
Evidence:
* [Scan Result]: The ffuf scan completed successfully but returned no matches for hidden files or directories using the wordlists/short.txt wordlist.
* [Target Behavior]: All requests returned 404 Not Found or were filtered out by the -fc 404 flag.
Analysis & Reasoning:
- No useful paths were found.
Unknowns:
- Whether deeper paths exist.
Next Steps:
* [Command] Deeper Scan: Run ffuf with the wordlists/medium.txt wordlist.
""",
        tool_results=[
            {
                "success": True,
                "command": "ffuf",
                "full_command": "ffuf -u http://scanme.nmap.org/FUZZ -w wordlists/short.txt -ic -mc all -fc 404",
                "stdout": "index [Status: 200, Size: 6974, Words: 495, Lines: 153, Duration: 288ms] images [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 245ms] .htaccess [Status: 403, Size: 291, Words: 21, Lines: 11, Duration: 220ms]",
            }
        ],
        prompt="ffuf -u http://scanme.nmap.org/FUZZ -w wordlists/short.txt -ic -mc all -fc 404",
        target="http://scanme.nmap.org",
    )

    lowered = repaired.lower()
    assert "no hidden files or directories were discovered" not in lowered
    assert "returned no matches" not in lowered
    assert "ffuf matched `index` with http 200" in lowered
    assert "ffuf matched `images` with http 301" in lowered
    assert "ffuf matched `.htaccess` with http 403" in lowered
