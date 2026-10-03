# Testing and Validation

This directory documents the security tests used to validate the GCP SOC Automation Lab and confirm that events successfully travel through the detection, AI analysis, automation, and incident-management pipeline.

## Validation Strategy

The lab was tested in multiple stages rather than relying only on individual component checks.

The primary validation paths were:

1. **EICAR → Microsoft Defender → Wazuh**
2. **Wazuh → Vertex AI → Structured SOC Incident**
3. **Structured Incident → JSONL + Cloud Storage + BigQuery + Pub/Sub**
4. **Structured Incident → Shuffle SOAR → TheHive**

These tests verified both security-event detection and end-to-end automation.

## EICAR Detection Test

The EICAR antivirus test file was used to safely generate a Microsoft Defender malware detection on the Windows endpoint.

The validation path was:

**EICAR → Microsoft Defender → Windows Event Log → Wazuh Agent → Wazuh Manager**

Microsoft Defender generated security events including the EICAR threat detection, which were collected by the Wazuh agent and forwarded to the Wazuh Manager.

Wazuh processed the Defender event and generated a high-severity security alert for further analysis.

## AI Alert Analysis Test

High-severity Wazuh alerts were processed by the custom AI alert analyzer.

The validation path was:

**Wazuh Alert → Severity Filter → Deduplication → Vertex AI → Structured Incident**

The analyzer successfully:

- Detected qualifying Wazuh alerts.
- Extracted relevant security-event context.
- Submitted the alert context to Vertex AI.
- Validated the structured AI response.
- Generated a standardized incident object.
- Assigned a unique incident ID.

The resulting incident included fields such as verdict, risk, confidence, evidence, investigation steps, and recommended action.

## Incident Persistence and Distribution

The generated incident was validated across multiple destinations.

The incident was successfully:

- Appended to the local JSONL incident store.
- Archived in Google Cloud Storage.
- Inserted into BigQuery.
- Published to Pub/Sub.

This demonstrated that a single analyzed security event could be persisted and distributed across multiple cloud services.

## SOAR and TheHive Automation Test

The structured incident was also sent automatically to the Shuffle webhook.

The validation path was:

**Wazuh → Vertex AI → Structured Incident → Shuffle → TheHive**

Shuffle received the incident payload and executed the configured workflow.

The workflow dynamically mapped incident fields into a TheHive alert, including:

- Incident ID
- Alert summary
- Wazuh rule information
- AI verdict
- Risk
- Confidence
- Recommended action

The alert was then automatically created in TheHive without requiring manual incident creation.

## Final End-to-End Validation

The final test validated the complete SOC automation pipeline:

**Windows Endpoint → Defender / Sysmon → Wazuh → Vertex AI → Structured Incident → Cloud Services + Shuffle → TheHive**

This confirmed that the major components of the project were integrated successfully and that a security event generated on the monitored endpoint could progress from detection through AI-assisted analysis, cloud persistence, automation, and incident management.

## Evidence

Implementation and testing screenshots are available in the repository's `Evidence/` directory.

The evidence set documents the project progressively, including:

- Wazuh deployment and endpoint enrollment
- Microsoft Defender detection
- Vertex AI alert analysis
- Structured incident generation
- Shuffle and TheHive integration
- Pub/Sub publishing
- BigQuery persistence
- Cloud Storage archival
- Final automated TheHive incident creation

## Safety

The EICAR test file is a standardized antivirus testing artifact and was used only to safely trigger antivirus detection behavior.

No real malware is included in this repository.
