# GCP SOC Automation Lab - AI Alert Analyzer
# Sanitized public example based on the final lab implementation.
# Replace placeholder values with your own environment-specific configuration.
# Do not commit credentials, API keys, webhook identifiers, or other secrets.

import json
import time
import uuid
import urllib.request
from pathlib import Path
from google import genai
from google.cloud import pubsub_v1
from google.cloud import bigquery
from google.cloud import storage

ALERT_FILE = Path("/var/ossec/logs/alerts/alerts.json")
MIN_LEVEL = 12
COOLDOWN_SECONDS = 300  # 5 minutes
INCIDENT_FILE = "/opt/wazuh-ai-analyzer/incidents.jsonl"

PUBSUB_PROJECT_ID = "YOUR_GCP_PROJECT_ID"
PUBSUB_TOPIC_ID = "soc-ai-incidents"

BIGQUERY_PROJECT_ID = "YOUR_GCP_PROJECT_ID"
BIGQUERY_DATASET_ID = "soc_incidents"
BIGQUERY_TABLE_ID = "ai_incidents"

GCS_PROJECT_ID = "YOUR_GCP_PROJECT_ID"
GCS_BUCKET_NAME = "YOUR_GCS_BUCKET_NAME"

SHUFFLE_WEBHOOK_URL = (
    "http://SHUFFLE_SERVER_IP:3001/api/v1/hooks/"
    "YOUR_WEBHOOK_ID"
)

recent_alerts = {}

client = genai.Client(
    vertexai=True,
    project="YOUR_GCP_PROJECT_ID",
    location="us-central1"
)

def decode_process_access(access_hex):
    if not access_hex:
        return []

    try:
        access = int(access_hex, 16)
    except (ValueError, TypeError):
        return ["Unknown"]

    access_rights = {
        0x0001: "PROCESS_TERMINATE",
        0x0002: "PROCESS_CREATE_THREAD",
        0x0004: "PROCESS_SET_SESSIONID",
        0x0008: "PROCESS_VM_OPERATION",
        0x0010: "PROCESS_VM_READ",
        0x0020: "PROCESS_VM_WRITE",
        0x0040: "PROCESS_DUP_HANDLE",
        0x0080: "PROCESS_CREATE_PROCESS",
        0x0100: "PROCESS_SET_QUOTA",
        0x0200: "PROCESS_SET_INFORMATION",
        0x0400: "PROCESS_QUERY_INFORMATION",
        0x0800: "PROCESS_SUSPEND_RESUME",
        0x1000: "PROCESS_QUERY_LIMITED_INFORMATION"
    }

    return [
        name
        for mask, name in access_rights.items()
        if access & mask
    ]

def is_known_noise(alert):
    rule = alert.get("rule", {})

    eventdata = (
        alert.get("data", {})
        .get("win", {})
        .get("eventdata", {})
    )

    source_image = eventdata.get("sourceImage", "").lower()
    target_image = eventdata.get("targetImage", "").lower()

    # Suppress known legitimate OneDrive -> Explorer ProcessAccess noise
    if (
        str(rule.get("id")) == "92910"
        and source_image.endswith("\\onedrive.exe")
        and target_image.endswith("\\explorer.exe")
    ):
        return True

    return False

def is_duplicate(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    eventdata = (
        alert.get("data", {})
        .get("win", {})
        .get("eventdata", {})
    )

    # Defender: use Detection ID so repeated alerts from the same
    # Defender detection are suppressed, while new detections pass.
    detection_id = eventdata.get("detection ID")

    if detection_id:
        event_key = (
            "defender",
            detection_id
        )

    # Sysmon Process Access events
    elif eventdata.get("sourceProcessGUID") or eventdata.get("targetProcessGUID"):
        event_key = (
            "sysmon_process_access",
            eventdata.get("sourceProcessGUID"),
            eventdata.get("targetProcessGUID"),
            eventdata.get("grantedAccess")
        )

    # Sysmon File Creation / other process events
    elif eventdata.get("processGUID") or eventdata.get("targetFilename"):
        event_key = (
            "sysmon_event",
            eventdata.get("processGUID"),
            eventdata.get("targetFilename")
        )

    # Generic fallback
    else:
        event_key = (
            "wazuh_event",
            alert.get("id")
        )

    fingerprint = (
        agent.get("id"),
        rule.get("id"),
        event_key
    )

    current_time = time.time()
    last_seen = recent_alerts.get(fingerprint)

    if last_seen and (current_time - last_seen) < COOLDOWN_SECONDS:
        return True

    recent_alerts[fingerprint] = current_time
    return False

def analyze_alert(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = rule.get("mitre", {})

    # Windows/Sysmon information
    eventdata = (
        alert.get("data", {})
        .get("win", {})
        .get("eventdata", {})
    )

    security_context = {
    # Core Wazuh information
    "timestamp": alert.get("timestamp"),
    "agent": agent.get("name"),
    "agent_ip": agent.get("ip"),
    "rule_id": rule.get("id"),
    "rule_level": rule.get("level"),
    "description": rule.get("description"),

    # MITRE ATT&CK information
    "mitre_id": mitre.get("id", []),
    "mitre_tactic": mitre.get("tactic", []),
    "mitre_technique": mitre.get("technique", []),

    # Microsoft Defender information
    "threat_name": eventdata.get("threat Name"),
    "threat_id": eventdata.get("threat ID"),
    "severity": eventdata.get("severity Name"),
    "category": eventdata.get("category Name"),
    "detection_time": eventdata.get("detection Time"),
    "detection_source": eventdata.get("source Name"),
    "detection_origin": eventdata.get("origin Name"),
    "detection_type": eventdata.get("type Name"),
    "detection_user": eventdata.get("detection User"),
    "process_name": eventdata.get("process Name"),
    "file_path": eventdata.get("path"),
    "execution_status": eventdata.get("execution Name"),
    "action": eventdata.get("action Name"),

    # Sysmon-compatible information
    "source_image": eventdata.get("sourceImage"),
    "target_image": eventdata.get("targetImage"),
    "granted_access": eventdata.get("grantedAccess"),
    "decoded_access_rights": decode_process_access(
        eventdata.get("grantedAccess")
    ),
    "source_user": eventdata.get("sourceUser"),
    "target_user": eventdata.get("targetUser"),
    }

    prompt = f"""
You are assisting a SOC analyst.

Analyze this real Wazuh security alert:

{json.dumps(security_context, indent=2)}

Return ONLY valid JSON. Do not use Markdown, code fences, or text
before or after the JSON.

Use exactly this structure:

{{
  "verdict": "Benign | Suspicious | Malicious | Needs Investigation",
  "risk": "Low | Medium | High | Critical",
  "confidence": "Low | Medium | High",
  "alert_summary": "Concise description of what happened",
  "why_it_triggered": "Explain why the security alert triggered",
  "evidence": [
    "Important fact from the alert",
    "Important fact from the alert"
  ],
  "possible_false_positive": "Explain plausible benign context",
  "mitre_context": "Relevant MITRE ATT&CK context, or Not Applicable",
  "investigation_steps": [
    "Investigation step 1",
    "Investigation step 2"
  ],
  "recommended_action": "Concise recommendation for the SOC analyst"
}}

Important rules:
- Base conclusions only on the supplied alert data.
- Do not assume an alert is malicious solely because its Wazuh
  severity is high.
- Clearly distinguish confirmed facts from possible malicious behavior.
- If information is unavailable, say "Unknown" rather than inventing it.
- If the alert is a known security test such as EICAR, identify that
  context while still explaining why the security control detected it.
- For Sysmon process-access events, use "decoded_access_rights" as the
  authoritative interpretation of "granted_access". Do not independently
  reinterpret or decode the hexadecimal access mask.
"""

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt
    )

    print("\n" + "=" * 70)
    print("AI SOC ALERT ANALYSIS")
    print("=" * 70)
    print(
        f"Agent: {agent.get('name')} | "
        f"Rule: {rule.get('id')} | "
        f"Level: {rule.get('level')}"
    )
    print("=" * 70)

    # Validate Gemini output as machine-readable JSON
    raw_response = response.text.strip()

    # Remove Markdown code fences if Gemini adds them
    if raw_response.startswith("```json"):
        raw_response = raw_response[7:]
    elif raw_response.startswith("```"):
        raw_response = raw_response[3:]

    if raw_response.endswith("```"):
        raw_response = raw_response[:-3]

    raw_response = raw_response.strip()

    try:
        ai_analysis = json.loads(raw_response)

        print("JSON validation: SUCCESS")
        print(json.dumps(ai_analysis, indent=2))


        return ai_analysis

    except json.JSONDecodeError as error:
        print("JSON validation: FAILED")
        print(f"Parsing error: {error}")
        print("Raw AI response:")
        print(response.text)


        return None

    print("=" * 70)

def build_incident(alert, ai_analysis):
    if not ai_analysis:
        return None

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    incident = {
        "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": alert.get("timestamp"),
        "agent": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "verdict": ai_analysis.get("verdict"),
        "risk": ai_analysis.get("risk"),
        "confidence": ai_analysis.get("confidence"),
        "alert_summary": ai_analysis.get("alert_summary"),
        "evidence": ai_analysis.get("evidence", []),
        "investigation_steps": ai_analysis.get("investigation_steps", []),
        "recommended_action": ai_analysis.get("recommended_action")
    }

    return incident

def save_incident(incident):
    if not incident:
        return

    with open(INCIDENT_FILE, "a", encoding="utf-8") as incident_file:
        incident_file.write(json.dumps(incident) + "\n")

    print(f"Incident saved to: {INCIDENT_FILE}")

def archive_to_gcs(incident):
    if not incident:
        return False

    try:
        storage_client = storage.Client(project=GCS_PROJECT_ID)
        bucket = storage_client.bucket(GCS_BUCKET_NAME)

        incident_id = incident.get("incident_id")
        object_name = f"incidents/{incident_id}.json"

        blob = bucket.blob(object_name)

        blob.upload_from_string(
            json.dumps(incident, indent=2),
            content_type="application/json"
        )

        print(
            f"Incident archived to GCS: "
            f"{incident_id} | "
            f"gs://{GCS_BUCKET_NAME}/{object_name}"
        )

        return True

    except Exception as error:
        print(f"Failed to archive incident to GCS: {error}")
        return False

def insert_into_bigquery(incident):
    if not incident:
        return False

    try:
        client = bigquery.Client(project=BIGQUERY_PROJECT_ID)

        table_id = (
            f"{BIGQUERY_PROJECT_ID}."
            f"{BIGQUERY_DATASET_ID}."
            f"{BIGQUERY_TABLE_ID}"
        )

        row = incident.copy()

        # Normalize Wazuh timestamp for BigQuery.
        timestamp = row.get("timestamp")
        if timestamp:
            row["timestamp"] = timestamp.replace("+0000", "+00:00")

        # BigQuery columns are STRING, so serialize list fields.
        row["evidence"] = json.dumps(
            incident.get("evidence", [])
        )
        row["investigation_steps"] = json.dumps(
            incident.get("investigation_steps", [])
        )

        errors = client.insert_rows_json(
            table_id,
            [row],
            row_ids=[incident.get("incident_id")]
        )

        if errors:
            print(f"Failed to insert incident into BigQuery: {errors}")
            return False

        print(
            f"Incident inserted into BigQuery: "
            f"{incident.get('incident_id')}"
        )
        return True

    except Exception as error:
        print(f"Failed to insert incident into BigQuery: {error}")
        return False

def publish_to_pubsub(incident):
    if not incident:
        return False

    try:
        publisher = pubsub_v1.PublisherClient()

        topic_path = publisher.topic_path(
            PUBSUB_PROJECT_ID,
            PUBSUB_TOPIC_ID
        )

        message_data = json.dumps(incident).encode("utf-8")

        future = publisher.publish(
            topic_path,
            message_data
        )

        message_id = future.result(timeout=10)

        print(
            f"Incident published to Pub/Sub: "
            f"{incident.get('incident_id')} | "
            f"Message ID: {message_id}"
        )

        return True

    except Exception as error:
        print(f"Failed to publish incident to Pub/Sub: {error}")
        return False

def send_to_shuffle(incident):
    if not incident:
        return False

    try:
        payload = json.dumps(incident).encode("utf-8")

        request = urllib.request.Request(
            SHUFFLE_WEBHOOK_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(request, timeout=10) as response:
            response_body = response.read().decode("utf-8")

            if response.status == 200:
                print(
                    f"Incident sent to Shuffle: "
                    f"{incident.get('incident_id')}"
                )
                print(f"Shuffle response: {response_body}")
                return True

            print(f"Shuffle returned HTTP {response.status}")
            return False

    except Exception as error:
        print(f"Failed to send incident to Shuffle: {error}")
        return False

def monitor():
    print("Wazuh AI Analyzer started")
    print(f"Monitoring: {ALERT_FILE}")
    print(f"AI threshold: Wazuh Level {MIN_LEVEL}+")

    with ALERT_FILE.open("r") as logfile:

        # Start at the end so old alerts aren't sent to Vertex AI.
        logfile.seek(0, 2)

        while True:
            line = logfile.readline()

            if not line:
                time.sleep(1)
                continue

            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            level = alert.get("rule", {}).get("level", 0)

            if level < MIN_LEVEL:
                continue

            if is_known_noise(alert):
                print(
                    f"Known-noise alert suppressed: "
                    f"Rule {alert.get('rule', {}).get('id')}"
                )
                continue

            if is_duplicate(alert):
                print(
                    f"Duplicate alert skipped: "
                    f"Rule {alert.get('rule', {}).get('id')}"
                )
                continue

            print(
                f"\nHigh-severity alert detected: "
                f"Level {level}"
            )

            try:
                ai_analysis = analyze_alert(alert)

                incident = build_incident(alert, ai_analysis)

                if incident:
                    print("\nINCIDENT OBJECT CREATED")
                    print(json.dumps(incident, indent=2))
                    save_incident(incident)
                    archive_to_gcs(incident)
                    insert_into_bigquery(incident)
                    publish_to_pubsub(incident)
                    send_to_shuffle(incident)

            except Exception as error:
                print(f"AI analysis failed: {error}")


if __name__ == "__main__":
    monitor()
