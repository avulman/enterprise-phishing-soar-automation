# Enterprise Phishing SOAR Automation

Enterprise-grade phishing triage and automated incident response for Microsoft 365: ingest user-reported phishing, reconstruct the original message, extract IOCs (URLs/domains/IPs/attachments), enrich with threat intel, score risk, create ServiceNow incidents, and maintain mailbox state for reliable, repeatable processing.
---

## End-to-end lifecycle

When a user reports a suspicious email in Outlook:
1. Microsoft creates a **report wrapper** and forwards it to a dedicated mailbox (e.g., 'reportedemails@domain...').
2. A mailbox rule moves the wrapper email from the inbox, to a **Reported Emails** folder.
3. The SOAR engine detects new items via **Microsoft Graph delta queries**.
4. The system reconstructs the original email (RFC 822) / '.eml') and performs:
  - Display of authentication (SPF/DKIM/DMARC, hop chain)
  - IOC extraction (URLs, domains, email addresses, IPs)
  - Attachment handling (download, file type, hashing, optional intel lookups)
5. Indicators are enriched using **VirusTotal** and **AbuseIPDB**.
6. A scoring engine classifies the email (SAFE / SUSPICIOUS / MALICIOUS).
7. A **ServiceNow Incident** is created with full context and evidence.
8. The wrapper (and/or original artifacts) are moved to **Processed** for idempotency and auditability.

---

## Key Capabilities

### 1) Automated ingestion via Graph Delta
- Efficiently monitors the **Reported Emails** folder without re-reading old messages
- Tracks state (delta token / processed IDs) for idempotent processing
- Designed to run continuously (cron / systemd / container)

---

### 2) Original email reconstruction (RFC 822)
- Extracts the original message from the wrapper attachment ('.eml')
- Full headers
- MIME boundaries
- Attachments
- SMTP routing hops

---

### 3) IOC extraction
Extracts and normalizes:
- URLs (parsing + hostname extraction)
- Domains (from body text + URL hostnames)
- Email addresses
- IP addresses (primarily from 'Received:' chains and relevant headers)

--- 

### 4) Attachment processing
- Enumerates attachments and downloads content where applicable
- Computes file fingerprints for correlation and reputation lookup:
  - SHA256
  - MD5
- Supports common phishing attachment types:
  - HTML
  - PDF
  - Office documents
  - Archives
 
---

### 5) Threat intelligence enrichment
External intelligence sources provide real-world reputation context:
- **VirusTotal**
  - URL reputation
  - Domain reputation
  - IP reputation
  - File hash detections
 
- **AbuseIPDB**
  - IP abuse reputation
  - Abuse confidence score
  - Infrastructure attribution context
 
--- 
### 6) Scoring & classification
Combines forensic signals and threat intelligence into a unified risk score.

Classification outcomes:

- **SAFE**
  - Low risk
  - Documented for audit trail
  - Close ticket functionality could be implemented if further scoring logic is built out

- **SUSPICIOUS**
  - Requires analyst review

- **MALICIOUS**
  - Triggers containment-ready workflow
 
### 7) ServiceNow incident creation

Automatically creates incident tickets containing:

- Reporter identity
- Sender information
- Subject and timestamps
- Threat score and classification
- Extracted IOCs and enrichment results
- Human-readable forensic summary

Provides complete auditability and SOC visibility.

### 8) Mailbox state management

- Moves processed emails to the **Processed** folder  
- Prevents duplicate analysis  
- Supports auditability and controlled reprocessing  

---

## Tech Stack

Core technologies used:

- Python 3  
- Microsoft Graph API (Exchange Online mailbox access)
- Microsoft Defender for o365
- ServiceNow REST API (incident management)  
- VirusTotal API (threat intelligence)  
- AbuseIPDB API (IP reputation intelligence)  
- OAuth2 Client Credentials flow (Azure AD application authentication)

---

## Permissions (Azure AD / Microsoft Graph)

Uses **Application permissions** (admin consent required).

Mail.Read (Application) - minimum permission to read mail from 'Reported Emails' inbox
Mail.ReadWrite (Application) - performing mailbox state modification
Use Exchange Application Access Policies to restrict mailbox scope and enforce least privilege access.

--- 

## Configuration

Store secrets in environment variables.

Example `.env` file:
# Azure / Microsoft Graph
TENANT_ID="..."
CLIENT_ID="..."
CLIENT_SECRET="..."
MAILBOX="reportedemails@yourtenant.onmicrosoft.com"

# ServiceNow
SN_INSTANCE="https://devXXXXX.service-now.com"
SN_CLIENT_ID="..."
SN_CLIENT_SECRET="..."

# Threat Intelligence
VT_API_KEY="..."
ABUSEIPDB_API_KEY="..."