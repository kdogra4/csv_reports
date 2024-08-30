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
ENDOR_NAMESPACE = os.getenv('ENDOR_NAMESPACE')
API_URL = 'https://api.endorlabs.com/v1'

def get_token():
    api_key = os.getenv('API_KEY')
    api_secret = os.getenv('API_SECRET')
    url = f'{API_URL}/auth/api-key'
    payload = {
        'key': api_key,
        'secret': api_secret
    }
    headers = {
        'Content-Type': 'application/json',
        'Request-Timeout': '60'
    }

    response = requests.post(url, json=payload, headers=headers, timeout=60)
    
    if response.status_code == 200:
        token = response.json().get('token')
        return token
    else:
        raise Exception(f'Failed to get token: {response.status_code}, {response.text}')

API_TOKEN = get_token()
HEADERS = {
    'User-Agent': 'curl/7.68.0',
    'Accept': '*/*',
    'Authorization': f'Bearer {API_TOKEN}',
    'Request-Timeout': '60'  # Set the request timeout to 60 seconds
}

def get_projects(tags=None):
    print('Fetching projects...')
   
    url = f'{API_URL}/namespaces/{ENDOR_NAMESPACE}/projects'
    
    params = {'list_parameters.mask': 'uuid,meta.name'}
    if tags:
        tags_filter = ' or '.join([f'meta.tags==\'{tag}\'' for tag in tags])
        params['list_parameters.filter'] = tags_filter
    
    projects = []
    next_page_id = None

    while True:
        if next_page_id:
            params['list_parameters.page_id'] = next_page_id

        response = requests.get(url, headers=HEADERS, params=params, timeout=60)

        if response.status_code != 200:
            print(f'Failed to get projects, Status Code: {response.status_code}, Response: {response.text}')
            exit()

        response_data = response.json()
        fetched_projects = response_data.get('list', {}).get('objects', [])
        projects.extend([{'uuid': project['uuid'], 'name': project['meta']['name']} for project in fetched_projects])

        next_page_id = response_data.get('list', {}).get('response', {}).get('next_page_id')
        if not next_page_id:
            break

    print(f'Total projects fetched: {len(projects)}')
    return projects

def get_packages(projects):
    url= f'{API_URL}/namespaces/{ENDOR_NAMESPACE}/package-versions'
    all_packages=[]
    for project in projects:
        project_name = project['name']
        project_uuid = project['uuid']
        params = {'list_parameters.filter': f"spec.project_uuid=={project_uuid} and context.type in [CONTEXT_TYPE_MAIN, CONTEXT_TYPE_REF]",
        'list_parameters.mask': 'uuid,meta.name,context'}

        next_page_id = None
        package_count = 0

        while True:
            if next_page_id:
                params['list_parameters.page_id'] = next_page_id

            response = requests.get(url, headers=HEADERS, params=params, timeout=60)

            if response.status_code != 200:
                print(f'Failed to get packages, Status Code: {response.status_code}, Response: {response.text}')
                exit()

            response_data = response.json()
            fetched_packages = response_data.get('list', {}).get('objects', [])
            for package in fetched_packages:
                list_item = [{'project_uuid': project_uuid, 'project_name': project_name, 'package_uuid': package['uuid'], 'package_name': package['meta']['name'], 'context_id': package['context']['id']}]
                all_packages.extend(list_item)
                package_count += 1
            next_page_id = response_data.get('list', {}).get('response', {}).get('next_page_id')

            if not next_page_id:
                break
        print(f"Package Count: {package_count} for Project: {project_name}")
    return all_packages


def get_findings(packages):
    all_findings = []
    url = f'{API_URL}/namespaces/{ENDOR_NAMESPACE}/findings'
    for package in packages:
        project_name = package['project_name']
        project_uuid = package['project_uuid']
        package_uuid = package['package_uuid']
        package_name = package['package_name']
        print(f'Fetching findings for package {package_uuid} ({package_name})...')
        params = {
            'list_parameters.filter': f'meta.parent_uuid=={package_uuid} and spec.finding_categories==FINDING_CATEGORY_VULNERABILITY and spec.level in [FINDING_LEVEL_CRITICAL, FINDING_LEVEL_HIGH] )',
        'list_parameters.mask': 'uuid,meta,spec.finding_metadata.vulnerability'
        }

        next_page_id = None

        while True:
            if next_page_id:
                params['list_parameters.page_id'] = next_page_id

            response = requests.get(url, headers=HEADERS, params=params, timeout=60)
            if response.status_code != 200:
                print(f'Failed to get findings for project {project_uuid}, Status Code: {response.status_code}, Response: {response.text}')
                break

            response_data = response.json()
            findings = response_data.get('list', {}).get('objects', [])

            for finding in findings:
                try:
                    finding_metadata = finding.get('spec', {}).get('finding_metadata', {})
                    vulnerability_meta = finding_metadata.get('vulnerability', {}).get('meta', {})
                    vulnerability_spec = finding_metadata.get('vulnerability', {}).get('spec', {})
                    
                    #Check if CVSS exists
                    cve_id = vulnerability_meta.get('name', '') if vulnerability_meta.get('name', '').startswith('CVE') else ''
                    if not cve_id:
                        aliases = vulnerability_spec.get('aliases') if vulnerability_spec else []
                        for alias in aliases:
                            if alias.startswith('CVE'):
                                cve_id = alias
                                break

                    #Check if CVSS exists
                    cvss_v3_severity = vulnerability_spec.get('cvss_v3_severity', {}) if vulnerability_spec else []
                    cvss_severity_level = cvss_v3_severity.get('level', '') if cvss_v3_severity else ''
                    cvss_severity_score = cvss_v3_severity.get('score', '') if cvss_v3_severity else ''
                    cvss_severity_vector= cvss_v3_severity.get('vector', '') if cvss_v3_severity else ''

                    # #Check if CISA KEV exists 
                    kev_record = vulnerability_spec.get('raw', {}).get('kev_record', {}) if vulnerability_spec else []
                    kev_due_date = kev_record.get('due_date', '') if kev_record else ''
                    kev_date_added = kev_record.get('date_added', '') if kev_record else ''


                    #Check if EPSS Probability exists
                    epss_record = vulnerability_spec.get('raw', {}).get('epss_record', {}) if vulnerability_spec else []
                    epss_probability = epss_record.get('probability', {}) if epss_record else ''

                    extracted_finding = {
                        'project_name': package['project_name'],
                        'project_uuid': package['project_uuid'],
                        'package_name': package_name,
                        'context_id': package['context_id'],
                        'package_uuid': package_uuid,
                        'finding_uuid': finding['uuid'],
                        'name': finding['meta'].get('name'),
                        'description': finding['meta'].get('description'),
                        'vulnerability_name': vulnerability_meta.get('name'),
                        'vulnerability_description': vulnerability_meta.get('description'),
                        'cve_id': cve_id,
                        'cvss_severity_level': cvss_severity_level,
                        'cvss_severity_score': cvss_severity_score,
                        'cvss_severity_vector': cvss_severity_vector,
                        'kev_due_date': kev_due_date,
                        'kev_date_added': kev_date_added,
                        'epss_probability': epss_probability,
                        'create_time': finding['meta'].get('create_time')
                    }
                    all_findings.append(extracted_finding)
                except Exception as e:
                    print(f"Failed to process finding:{finding.get('uuid', 'unknown')}, Error: {str(e)}")

            next_page_id = response_data.get('list', {}).get('response', {}).get('next_page_id')
            if not next_page_id:
                break
    
    print(f'Total Findings Fetched: {len(all_findings)}')
    return all_findings

def save_findings_to_csv(findings, filename='findings.csv'):
    fieldnames = ['project_name', 'project_uuid', 'package_name', 'context_id', 'package_uuid', 'finding_uuid', 'name', 'description', 'vulnerability_name', 'vulnerability_description', 'cve_id', 'cvss_severity_level', 'cvss_severity_score', 'cvss_severity_vector', 'kev_due_date', 'kev_date_added', 'epss_probability', 'create_time']
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)
    print(f'Findings saved to {filename}')

def main():
    parser = argparse.ArgumentParser(description='SBOM Exporter')
    parser.add_argument('--project_tags', type=str, help='Comma-separated list of project tags to filter by')
    args = parser.parse_args()

    tags = args.project_tags.split(',') if args.project_tags else None
    if tags:
        tags = [tag.strip() for tag in tags]

    projects = get_projects(tags)
    if not projects:
        print('No projects found with the specified tags.')
        return
    
    packages = get_packages(projects)


    findings = get_findings(packages)
    if findings:
        # Save findings to a JSON file
        with open('findings.json', 'w') as f:
            json.dump(findings, f, indent=2)
        print('Findings saved to findings.json')

        # Save findings to a CSV file
        save_findings_to_csv(findings, 'findings.csv')
    else:
        print('No findings found for the specified projects.')

if __name__ == '__main__':
    main()