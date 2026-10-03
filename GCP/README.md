# Google Cloud Platform Integration

This directory documents the Google Cloud services used to extend the GCP SOC Automation Lab with AI-assisted alert analysis, event distribution, historical analytics, and incident archival.

## Role in the Architecture

Google Cloud provides the infrastructure and managed services supporting the SOC automation pipeline.

The main cloud-integrated workflow is:

**Windows Endpoint → Wazuh → Vertex AI → Structured SOC Incident**

After the AI analyzer creates a standardized incident, the incident is distributed to multiple destinations:

**Structured Incident → JSONL + Cloud Storage + BigQuery + Pub/Sub + Shuffle → TheHive**

## Google Cloud Services

### Compute Engine

Compute Engine hosts the core SOC infrastructure.

The lab uses separate virtual machines for:

- Wazuh Manager
- Shuffle SOAR
- TheHive

Separating the major components provides a more realistic distributed SOC architecture and allows the services to communicate over the Google Cloud network.

### Vertex AI

Vertex AI provides AI-assisted analysis for qualifying Wazuh security alerts.

The custom Python analyzer sends high-severity alert context to the Gemini model and receives structured SOC investigation results including:

- Verdict
- Risk
- Confidence
- Alert summary
- Trigger reason
- Evidence
- Investigation steps
- Recommended action

The returned data is validated before being converted into the standardized incident object used by the rest of the automation pipeline.

### Pub/Sub

Pub/Sub is used to publish structured SOC incidents to an event-driven messaging layer.

This demonstrates how security incidents can be distributed to additional consumers without tightly coupling those consumers to the Wazuh AI analyzer.

### BigQuery

BigQuery stores structured incident records for historical SOC analysis.

Persisting incidents in BigQuery allows security data to be queried and analyzed over time using fields such as:

- Incident ID
- Timestamp
- Agent
- Wazuh rule
- Risk
- Verdict
- Confidence
- Alert summary

### Cloud Storage

Google Cloud Storage provides durable archival of AI-generated incident records.

Each structured incident can be preserved independently from the local analyzer, providing an additional cloud-based record of security events.

## Security

Sensitive Google Cloud information is not published in this repository.

The following values are excluded or replaced with placeholders where applicable:

- Credentials
- Service-account secrets
- API keys
- Authentication tokens
- Public IP addresses
- Webhook identifiers

Access to Google Cloud services is provided through IAM permissions assigned to the required service identities rather than embedding credentials in the public project files.
