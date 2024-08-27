import requests
import json
import csv
from dotenv import load_dotenv
import os
import re
import argparse

# Load the environment variables from the .env file
load_dotenv()

# Get the API key and secret from environment variables
ENDOR_NAMESPACE = os.getenv("ENDOR_NAMESPACE")
API_URL = 'https://api.endorlabs.com/v1'

def get_token():
    api_key = os.getenv("API_KEY")
    api_secret = os.getenv("API_SECRET")
    url = f"{API_URL}/auth/api-key"
    payload = {
        "key": api_key,
        "secret": api_secret
    }
    headers = {
        "Content-Type": "application/json",
        "Request-Timeout": "60"
    }

    response = requests.post(url, json=payload, headers=headers, timeout=60)
    
    if response.status_code == 200:
        token = response.json().get('token')
        return token
    else:
        raise Exception(f"Failed to get token: {response.status_code}, {response.text}")

API_TOKEN = get_token()
HEADERS = {
    "User-Agent": "curl/7.68.0",
    "Accept": "*/*",
    "Authorization": f"Bearer {API_TOKEN}",
    "Request-Timeout": "60"  # Set the request timeout to 60 seconds
}

def get_projects(tags=None):
    print("Fetching projects...")
   
    url = f"{API_URL}/namespaces/{ENDOR_NAMESPACE}/projects"
    
    params = {'list_parameters.mask': 'uuid,meta.name'}
    if tags:
        tags_filter = " or ".join([f'meta.tags==\"{tag}\"' for tag in tags])
        params['list_parameters.filter'] = tags_filter
    
    projects = []
    next_page_id = None

    while True:
        if next_page_id:
            params['list_parameters.page_id'] = next_page_id

        response = requests.get(url, headers=HEADERS, params=params, timeout=60)

        if response.status_code != 200:
            print(f"Failed to get projects, Status Code: {response.status_code}, Response: {response.text}")
            exit()

        response_data = response.json()
        fetched_projects = response_data.get('list', {}).get('objects', [])
        projects.extend([{"uuid": project['uuid'], "name": project['meta']['name']} for project in fetched_projects])

        next_page_id = response_data.get('list', {}).get('response', {}).get('next_page_id')
        if not next_page_id:
            break

    print(f"Total projects fetched: {len(projects)}")
    print(f"Projects: {projects}")
    return projects

def get_findings(projects):
    all_findings = []
    for project in projects:
        project_uuid = project["uuid"]
        project_name = project["name"]
        print(f"Fetching findings for project {project_uuid} ({project_name})...")
        url = f"{API_URL}/namespaces/{ENDOR_NAMESPACE}/findings"
        params = {
            'list_parameters.filter': f'spec.project_uuid=={project_uuid} and and spec.finding_categories contains ["FINDING_CATEGORY_VULNERABILITY"] and (spec.level=="FINDING_LEVEL_CRITICAL" or spec.level=="FINDING_LEVEL_HIGH")'
        }
        next_page_id = None

        while True:
            if next_page_id:
                params['list_parameters.page_id'] = next_page_id

            response = requests.get(url, headers=HEADERS, params=params, timeout=60)
            if response.status_code != 200:
                print(f"Failed to get findings for project {project_uuid}, Status Code: {response.status_code}, Response: {response.text}")
                break

            response_data = response.json()
            findings = response_data.get('list', {}).get('objects', [])
            for finding in findings:
                try:
                    finding_metadata = finding.get("spec", {}).get("finding_metadata", {})
                    vulnerability_meta = finding_metadata.get("vulnerability", {}).get("meta", {})
                    vulnerability_spec = finding_metadata.get("vulnerability", {}).get("spec", {})
                    
                    #Check if CVE exists
                    try:
                        cve_id = vulnerability_spec.get("raw", {}).get("endor_vulnerability", {}).get("cve_id", {})
                    except:
                        cve_id = ""

                    #Check if CVSS exists
                    try: 
                        cvss_v3_severity = vulnerability_spec.get("cvss_v3_severity", {})
                        cvss_severity_level = cvss_v3_severity.get("level", "")
                        cvss_severity_score = cvss_v3_severity.get("score", "")
                        cvss_severity_vector= cvss_v3_severity.get("vector", "")
                    except:
                        cvss_severity_level, cvss_severity_score, cvss_severity_vector = ""

                    #Check if CISA exists
                    try:
                        cisa_action_due = vulnerability_spec.get("raw", {}).get("nvd_vulnerability", {}).get("cve", {}).get("cisa_action_due", {})
                    except:
                        cisa_action_due = ""    

                    #Check if EPSS Probability exists
                    try:
                        epss_probability = vulnerability_spec.get("raw", {}).get("epss_record", {}).get("probability", {})
                    except:
                        epss_probability = ""

                    extracted_finding = {
                        "project_uuid": project_uuid,
                        "project_name": project_name,
                        "uuid": finding["uuid"],
                        "name": finding["meta"].get("name"),
                        "description": finding["meta"].get("description"),
                        "vulnerability_name": vulnerability_meta.get("name"),
                        "vulnerability_description": vulnerability_meta.get("description"),
                        "cve_id": cve_id,
                        "cvss_severity_level": cvss_severity_level,
                        "cvss_severity_score": cvss_severity_score,
                        "cvss_severity_vector": cvss_severity_vector,
                        "cisa_action_due": cisa_action_due,
                        "epss_probability": epss_probability,
                        "create_time": finding["meta"].get("create_time")
                    }
                    all_findings.append(extracted_finding)
                except Exception as e:
                    print(f"Failed to process finding: {finding.get('uuid', 'unknown')}, Error: {str(e)}")

            next_page_id = response_data.get('list', {}).get('response', {}).get('next_page_id')
            if not next_page_id:
                break
    
    print(f"Total critical or high findings fetched: {len(all_findings)}")
    return all_findings

def save_findings_to_csv(findings, filename='findings.csv'):
    fieldnames = ["project_uuid", "project_name", "uuid", "name", "description", "vulnerability_name", "vulnerability_description", "cve_id", "cvss_severity_level", "cvss_severity_score", "cvss_severity_vector", "cisa_action_due", "epss_probability", "create_time"]
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)
    print(f"Findings saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description="SBOM Exporter")
    parser.add_argument('--project_tags', type=str, help="Comma-separated list of project tags to filter by")
    args = parser.parse_args()

    tags = args.project_tags.split(',') if args.project_tags else None
    if tags:
        tags = [tag.strip() for tag in tags]

    projects = get_projects(tags)
    if not projects:
        print("No projects found with the specified tags.")
        return

    findings = get_findings(projects)
    if findings:
        # Save findings to a JSON file
        with open('findings.json', 'w') as f:
            json.dump(findings, f, indent=2)
        print("Findings saved to findings.json")

        # Save findings to a CSV file
        save_findings_to_csv(findings, 'findings.csv')
    else:
        print("No critical or high findings found for the specified projects.")

if __name__ == '__main__':
    main()