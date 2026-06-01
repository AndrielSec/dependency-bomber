import os
import json
import re
import sys
from typing import Dict, List, Any, Optional
import requests

OSV_API_URL = "https://api.osv.dev/v1/query"
LEVENSHTEIN_THRESHOLD = 1

POPULAR_PACKAGES = [
    "requests", "numpy", "pandas", "flask", "boto3", "cryptography", 
    "django", "ansible", "tensorflow", "scikit-learn", "urllib3", 
    "pydantic", "fastapi", "aiohttp", "pyyaml", "jinja2"
]

class RequirementsParser:
    
    @staticmethod
    def parse(file_path: str) -> Dict[str, str]:
        dependencies = {}
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Error: Specified file not found: {file_path}")

        pattern = re.compile(r"^([a-zA-Z0-9_\-\[\]]+)(==|>=|<=|>|<|~=)?(.*)$")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    line = line.split("#")[0].strip()
                    
                    match = pattern.match(line)
                    if match:
                        pkg_name = match.group(1).lower().strip()
                        version = match.group(3).strip() if match.group(3) else "unknown"
                        dependencies[pkg_name] = version
        except Exception as e:
            raise e
            
        return dependencies

class VulnerabilityScanner:
    
    def __init__(self, api_url: str = OSV_API_URL):
        self.api_url = api_url

    def check_package(self, name: str, version: str) -> List[Dict[str, Any]]:
        if version == "unknown":
            return []

        payload = {
            "version": version,
            "package": {
                "name": name,
                "ecosystem": "PyPI"
            }
        }
        
        try:
            response = requests.post(self.api_url, json=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get("vulns", [])
            return []
        except requests.exceptions.RequestException:
            return []

    @staticmethod
    def extract_fix_version(vuln_data: List[Dict[str, Any]]) -> Optional[str]:
        fix_versions = []
        for vuln in vuln_data:
            for affected in vuln.get("affected", []):
                for ranges in affected.get("ranges", []):
                    for event in ranges.get("events", []):
                        if "fixed" in event:
                            fix_val = event["fixed"]
                            if not re.match(r'^[a-f0-9]{40}$', fix_val) and not fix_val.startswith("300.") and not fix_val.startswith("111."):
                                fix_versions.append(fix_val)
        
        if fix_versions:
            return max(fix_versions, key=lambda v: [int(x) for x in re.findall(r'\d+', v)])
        return None

class TyposquattingDetector:
    
    def __init__(self, popular_packages: List[str] = POPULAR_PACKAGES, threshold: int = LEVENSHTEIN_THRESHOLD):
        self.popular_packages = [pkg.lower() for pkg in popular_packages]
        self.threshold = threshold

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def detect(self, package_name: str) -> Optional[str]:
        pkg_lower = package_name.lower()
        
        if pkg_lower in self.popular_packages:
            return None
            
        for popular_pkg in self.popular_packages:
            distance = self._levenshtein_distance(pkg_lower, popular_pkg)
            if 0 < distance <= self.threshold:
                return popular_pkg
        return None

class DependencyBomberCore:
    
    def __init__(self, target_path: str):
        self.target_path = target_path
        self.parser = RequirementsParser()
        self.scanner = VulnerabilityScanner()
        self.detector = TyposquattingDetector()

    def run_analysis(self) -> None:
        print(f"[*] Analyzing target file: '{self.target_path}'...\n")
        
        try:
            dependencies = self.parser.parse(self.target_path)
        except Exception as e:
            print(f"[-] Parsing failed: {e}")
            sys.exit(1)

        report_data = {
            "target_file": self.target_path,
            "total_dependencies": len(dependencies),
            "results": []
        }

        print(f"{'PACKAGE NAME':<16} {'VERSION':<10} {'TYPOSQUATTING RISK':<25} {'VULNERABILITY STATUS'}")
        print("-" * 90)

        critical_issue_found = False
        remediations = []

        for pkg_name, version in dependencies.items():
            typo_target = self.detector.detect(pkg_name)
            if typo_target:
                typo_status = f"SUSPICIOUS (-> {typo_target})"
                critical_issue_found = True
                remediations.append(f"[!] Remove '{pkg_name}' immediately! It might be a typosquatting attack on '{typo_target}'.")
            else:
                typo_status = "CLEAN"
            
            vulns = self.scanner.check_package(pkg_name, version)
            if vulns:
                vuln_status = f"ALERT ({len(vulns)} Vulns)"
                critical_issue_found = True
                fix_ver = self.scanner.extract_fix_version(vulns)
                if fix_ver:
                    remediations.append(f"[*] Upgrade '{pkg_name}=={version}' to '=={fix_ver}' to resolve known vulnerabilities.")
                else:
                    remediations.append(f"[*] '{pkg_name}=={version}' has active vulnerabilities. No auto-fix version found.")
            else:
                vuln_status = "CLEAN"
            
            print(f"{pkg_name:<16} {version:<10} {typo_status:<25} {vuln_status}")
            
            report_data["results"].append({
                "package": pkg_name,
                "version": version,
                "typosquatting_risk": bool(typo_target),
                "impersonated_package": typo_target,
                "is_vulnerable": bool(vulns),
                "vulnerabilities": [
                    {"id": v.get("id"), "summary": v.get("summary", "No summary")} for v in vulns
                ]
            })

        print("-" * 90)
        self._save_report(report_data)

        if remediations:
            print("\n[+] REMEDIATION & FIX SUGGESTIONS:")
            for fix in remediations:
                print(fix)
            print("-" * 90)

        if critical_issue_found:
            print("\n[-] [SECURITY GATE] FAILED: Vulnerabilities or Typosquatting risks detected!")
            sys.exit(1)
        else:
            print("\n[+] [SECURITY GATE] PASSED: All packages are clean.")
            sys.exit(0)

    def _save_report(self, data: Dict[str, Any], filename: str = "dependency_risk_report.json"):
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            print(f"[+] Audit report saved to: {filename}")
        except IOError as e:
            print(f"[-] Failed to write report: {e}")

if __name__ == "__main__":
    file_path = input("Enter the path to your requirements.txt: ").strip()
    
    if file_path and os.path.exists(file_path):
        bomber = DependencyBomberCore(target_path=file_path)
        bomber.run_analysis()
    else:
        print("[-] Invalid file path or file does not exist!")
        sys.exit(1)