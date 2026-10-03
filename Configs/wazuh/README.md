# Wazuh Configuration

This directory contains sanitized Wazuh configuration examples used in the GCP SOC Automation Lab.

## Role in the Architecture

Wazuh acts as the central SIEM platform for the project. Security telemetry generated on the Windows 10 endpoint is collected by the Wazuh agent and forwarded to the Wazuh Manager running on Google Cloud.

The endpoint telemetry includes:

- Microsoft Defender security events
- Sysmon telemetry
- Windows Security events
- Windows System events
- Windows Application events

Wazuh processes these events using detection rules and forwards qualifying high-severity alerts to the custom AI alert analyzer for further analysis with Vertex AI.

## Configuration Files

The sanitized configuration examples in this directory document the Wazuh components used to:

- Collect Windows event-channel telemetry.
- Collect Microsoft Defender events.
- Collect Sysmon events.
- Generate and process security alerts.
- Integrate Wazuh alerts with the AI-assisted SOC analysis pipeline.

## Security

Sensitive infrastructure information and credentials are not included in the public configurations.

Values such as external IP addresses, credentials, API keys, and other sensitive parameters are removed or replaced with placeholders.
