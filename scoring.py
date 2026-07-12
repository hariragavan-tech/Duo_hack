import pandas as pd
import json
from datetime import datetime

def load_dependencies():
    try:
        return pd.read_csv('sample_data/sbom_dependencies.csv')
    except Exception as e:
        print(f"Error loading dependencies: {e}")
        return None

def calculate_application_risks():
    try:
        # Load official files
        with open('sample_data/applications.json', 'r') as f:
            apps = json.load(f)
        with open('sample_data/vulnerability_db.json', 'r') as f:
            vuln_list = json.load(f)
        with open('sample_data/license_rules.json', 'r') as f:
            license_rules = json.load(f)
            
        deps_df = pd.read_csv('sample_data/sbom_dependencies.csv')
        
        # High performance indexing hash maps
        vuln_dict = {v['library']: v for v in vuln_list}
        lic_dict = {l['license']: l for l in license_rules}
        
        report_rows = []
        CURRENT_YEAR = 2026
        
        for app in apps:
            app_id = app['app_id']
            app_name = app['name']
            criticality = app['criticality']
            license_model = app['license_model']
            
            # Filter rows utilizing the exact official header: 'application_id'
            app_deps = deps_df[deps_df['application_id'] == app_id]
            
            total_vulns = 0
            max_cvss = 0.0
            license_penalty = 0
            maintenance_penalty = 0
            
            for _, row in app_deps.iterrows():
                lib_name = row['library']
                lib_lic = row['license']
                last_updated_str = str(row['last_updated'])
                
                # Check 1: Vulnerability catalog matching
                if lib_name in vuln_dict:
                    vuln = vuln_dict[lib_name]
                    total_vulns += 1
                    if vuln['cvss_score'] > max_cvss:
                        max_cvss = vuln['cvss_score']
                        
                # Check 2: License compliance parameters
                if lib_lic in lic_dict:
                    rule = lic_dict[lib_lic]
                    if license_model == 'proprietary' and not rule['compatible_with_proprietary']:
                        if rule['risk_level'] == 'CRITICAL':
                            license_penalty = max(license_penalty, 35)
                        elif rule['risk_level'] == 'HIGH':
                            license_penalty = max(license_penalty, 20)
                        else:
                            license_penalty = max(license_penalty, 10)
                            
                # Check 3: Maintenance age calculations (> 2 years from 2026 baseline)
                try:
                    updated_year = datetime.strptime(last_updated_str.strip(), "%Y-%m-%d").year
                    if (CURRENT_YEAR - updated_year) >= 2:
                        maintenance_penalty = min(maintenance_penalty + 5, 20)
                except:
                    pass
            
            # Compute operational score metrics
            base_score = (max_cvss * 5) + license_penalty + maintenance_penalty
            composite_risk_score = min(round(base_score, 1), 100.0)
            
            report_rows.append({
                "App ID": app_id,
                "Application Name": app_name,
                "Business Criticality": criticality,
                "Risk Score": composite_risk_score,
                "Total Vulnerabilities": total_vulns,
                "Max CVSS Severity": max_cvss
            })
            
        return pd.DataFrame(report_rows)
    except Exception as e:
        print(f"❌ Error compiling application risks: {str(e)}")
        return None