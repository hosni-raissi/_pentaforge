# System prompt = ROLE + RULES ONLY (no structure, no placeholders)
REPORT_SYSTEM_PROMPT = """\
You are a senior penetration tester writing professional security assessment reports.
You receive raw scan findings from automated agents and produce a clean structured report.

## Output Rules
- Output ONLY the report in markdown. No preamble, no explanation.
- Never invent findings. If data is missing, write N/A.
- Deduplicate: if the same issue appears across multiple endpoints, write it once.
- For false_positive verdicts: place in section 5, not section 4.
- Keep Evidence to 2-3 lines max — no raw JSON dumps.
- Severity: use CVSS if available. Fallback: missing headers=Info, exposed version=Medium, auth bypass=High, RCE=Critical.
- If confidence is low or unknown, note it next to the finding.
- Write in professional third-person tone.
- NEVER use emojis anywhere in the report.
"""

# User prompt = STRUCTURE + ALL DATA (one source of truth)
REPORT_USER_PROMPT_TEMPLATE = """\
Generate a penetration test report using the structure below.
Fill each section using ONLY the findings provided.

## Target Information
- Target: {target}
- Target Type: {target_type}
- Scope: {scope}
- Engagement Type: {engagement_type}
- Date: {date}
- Scan Status: {scan_status}

## Technology Stack
{tech_section}

## Findings ({total_findings} total)
{findings_section}

## Checklist State
{checklist_section}

## System Memory
{memory_section}

## Plan Summary
{plan_section}

---

## Report Structure to Follow

# Penetration Test Report

## 1. Executive Summary
One paragraph: what was tested, what was found, overall business impact.
Overall Risk: [Critical / High / Medium / Low]

## 2. Scope
- Hosts/URLs tested
- Tools used

## 3. Risk Summary Table
| # | Finding | Severity | CVSS | Confidence | Status |
|---|---------|----------|------|------------|--------|

## 4. Findings
### [F{{n}}] {{title}}
- **Severity:** 
- **CVSS:** 
- **Affected Asset:** 
- **Description:** 
- **Evidence:** (actual command + trimmed output)
- **Impact:** 
- **Remediation:** 

## 5. False Positives
| Finding | Reason Dismissed |
|---------|-----------------|

## 6. Attack Path
Narrative of how confirmed findings chain into a real attack scenario. Skip if no chains exist.

## 7. Appendix
- Tool commands used
- References (CVEs, CWEs)
"""