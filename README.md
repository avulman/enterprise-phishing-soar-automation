# Enterprise Phishing SOAR Automation

This is the documentation for a fully automated, enterprise-grade Security Orchestration, Automation, and Response (SOAR) pipeline for phishing incident triage and response within Microsoft 365 environments. This system programmatically ingests user-reported phishing submissions, reconstructs original email artifacts at the RFC 5322 level, performs deterministic and intelligence-driven indicator analysis, computes risk scoring based on multi-source threat intelligence, suggests remediation actions, and orchestrates automated incident creation and containment workflows via ServiceNow.

The platform is designed with production-grade principles including a modular design, idempotent processing, state persistence, fault tolerance, API rate-limit awareness, and least-privilege access control, enabling continuous and scalable autonomous phishing response operations.

This system also constructs a solid foundation for future scalability of logic and integration, allowing for even more advanced detection, scoring, and actionability. Recommended actions can be integrated with Defensive security tools to automatically perform containment and remediation actions. Some use cases include: automatically identifying if a malicious URL was navigated to in the environment, blocking a sender address from sending additional mail to user inboxes, or even remediating (deleting) similar malicious emails from user inboxes.

---

## End-to-end lifecycle

When a user reports a suspicious email in Outlook:
1. **Report Submission and Wrapper Generation**: Microsoft Defender for Office 365 encapsulates the reported message inside a structured "report wrapper" email and delivers it to a designated reporting mailbox. In enterprise environments, this is monitored by security analysts. This wrapper contains the original message as an RFC 822 (.eml) attachment along with reporting metadata.

2. **Mailbox Routing and Isolation**: Exchange Online mailbox rules automatically route report wrappers into a dedicated processing folder (e.g., Reported Emails), ensuring seperation from normal mail flow and enabling deterministic monitoring.

3. **Message Detection**: The SOAR engine continuously monitors the reporting mailbox using Microsoft Graph delta queries (/messages/delta), enabling efficient incremental synchronization without reprocessing previously analyzed messages. This ensures idempotent processing, efficient API utilization, stateless runtime safety with persisted state recovery.

4. **Forensic Email Reconstruction**: The original message is extracted from the wrapper's .eml attachment and parsed at the RFC 5322 and MIME layer, enabling full forensic reconstruction including:
  - Complete SMTP header chain
  - Authentication verdicts (SPF, DKIM, DMARC)
  - Message metadata and envelope fields
  - MIME mody structure
  - Embedded URLs and artifacts
  - Attachments and encoded content
This reconstruction enables accurate attribution analysis and sender infrastructure tracing.

5. **Indicator Extraction and Normalization**: The engine performs deterministic indicator extraction across headers, body content, and attachments, identifying and normalizing:
  - Fully qualified URLs
  - Domains and subdomains
  - Sender and embedded email addresses
  - IPv4 and IPv6 addresses extracted from SMTP routing chains
  - File hashes (SHA256) computed from attachment payloads

6. **Threat Intelligence Enrichment**: Extracted indicators are enriched via external threat intelligence platforms to provide real-world reputation context:
  - VirusTotal API v3
  - AbuseIPDB repuation database
Enrichmentincludes:
  - Detection counts across antivirus engines
  - Malicious/suspicious verdict aggregation
  - Infrastructure abuse confidence scoring
  - Geographic and ASN attribution metadata
  - File hash intelligence correlation

7. **Deterministic Risk Scoring Engine**: A custom scoring engine applies weighted scoring logic based on enrichment results, attachment reputation, and infrastructure risk indicators.
The scoring engine produces:
  - Numerical risk score
  - Deterministic verdict classification (SAFE/SUSPICIOUS/MALICIOUS)
  - Confidence score
  - Evidence-based justification reasons

8. **Automated Incident Creation (ServiceNow integration)**: Upon classification, the system automatically generates a structural incident within ServiceNow using OAuth2 authenticated REST API integration.
Incident payload includes:
  - Reporter identity
  - Sender attribution
  - Subject and timestamps
  - Indicator analysis results
  - Threat intelligence findings
  - Risk score and classification verdict
  - Full forensic analysis summary
This ensures immediate SOC visbility and standardized incident tracking.

9. **Post-Processing and State Persistence**: Following successful processing, wrapper emails are moved into a dedicated 'Processed' folder to prevent duplicate analysis and ensure deterministic workflow execution.
    Processing state is persisted locally using structured state tracking files, enabling:
  - Crash recovery
  - Idempotent reprocessing prevention
  - Continuous exceution across restarts

---

## Engine on Display:
In under 10 seconds:
<img width="1787" height="1527" alt="1" src="https://github.com/user-attachments/assets/3ad29506-6ce2-438a-85a0-00d28b937646" />
<img width="1792" height="1368" alt="2" src="https://github.com/user-attachments/assets/4c283eca-30ca-479d-b650-57438642e89f" />

The email gets relocated to the 'Processed' folder in the email reports inbox:
<img width="1088" height="407" alt="3" src="https://github.com/user-attachments/assets/e0cc9f21-ce04-4168-9b6a-99a2200044ad" />

A ServiceNow incident ticket gets created with prepopulated fields, ready for analyst analysis. At this stage, additional logic can be built out to integrate with security tools to perform actions such as block malicious hashes in EDR, block network traffic to/from a malicious sender IP, investigate if any users have navigated to the phishing URL within the phishing email, and much, much more.
<img width="1665" height="961" alt="4" src="https://github.com/user-attachments/assets/67faa512-fdde-4985-95e1-5b55d8e398d2" />

---

## Tech Stack

Core technologies used:

- Python 3  (primary runtime)
- Microsoft Graph API (Exchange Online Access)
- Microsoft Defender for Office 365
- ServiceNow REST API (incident management)  
- VirusTotal API v3  
- AbuseIPDB API 
- OAuth2 Client Credentials authentication (Azure AD)
- Exchange Online mailbox infrastructure

---

## Configuration

Cloud Accounts:
- Microsoft 365 Developer Tenant (E3)
- Microsoft Defender for Office365
- ServiceNow Developer Instance
- VirusTotal API Key
- AbuseIPDB API Key

Local Execution Environment:
- Ubuntu Server 22.04 LTS
- VirtualBox or VMWare
- Minimum 2 CPU cores
- 4 GB RAM
- 40 GB disk
Run SOAR engine with 'python3 main.py'

Mailboxes (add licenses: Exchange Online):
john.silly@yourtenant.onmicrosoft.com
lebronjames@yourtenant.onmicrosoft.com
reportedemails@yourtenant.onmicrosoft.com

Azure App Registration and Microsoft Graph Authentication:
Azure Application Registration allows the SOAR engine to authenticate to Microsoft Graph using OAuth2 Client Credentials flow.
Acquire Client ID and Tenant ID.
Add Mail.Read and Mail.ReadWrite permissions.

Client Secret:
Save secret value to enable OAuth authentication.

Store secrets in environment variables (.env file).

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

---

## Security Model and Access Control

Required Microsoft Graph permissions:
Mail.Read (Application) - read access to reporting mailbox
Mail.ReadWrite (Application) - post-processing message state management
Exchange Application Access Policies can be applied to restrict mailbox access scope.
All authentication is performed using secure OAuth2 Client Credentials flow.

ServiceNow Service Account:
Dedicated ServiceNow account (svc_soar) was provisioned to enable secure, programmatic incident creation.
The 'itil' role was assigned to create incident records, read incident metadata/status, and update incident fields.
ACL was configured to restrict the service account to the incident table (incident) via the Table API (/api/now/table/incident)

No credentials are stored in source code (no basic authentication).

--- 

