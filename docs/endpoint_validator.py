#!/usr/bin/env python3
"""
Validator script to ensure all documented API endpoints exist in the codebase
"""
import re
import os

def find_api_endpoints_in_code():
    """Find all @app.(get|post|put|delete) endpoints in main.py"""
    endpoints = set()
    
    with open('/mnt/Aquaman/upstream-healer/app/main.py', 'r') as f:
        content = f.read()
    
    # Find all FastAPI decorator patterns
    pattern = r'@app\.(get|post|put|delete)\s*\(\s*[\"|\']([^\"|\']*)[\"|\']'
    matches = re.findall(pattern, content)
    
    for method, path in matches:
        endpoints.add((method.lower(), path))
    
    return endpoints

def find_documented_endpoints_in_docs():
    """Parse the documentation file to extract documented endpoints"""
    documented = set()
    
    with open('/mnt/Aquaman/upstream-healer/docs/api_documentation.rst', 'r') as f:
        content = f.read()
    
    # Find all endpoint patterns in documentation
    # Look for GET, POST, PUT, DELETE lines
    pattern = r'(GET|POST|PUT|DELETE)\s+(.+?)(?:\s+|\n)'
    matches = re.findall(pattern, content)
    
    for method, path in matches:
        # Clean up the path - remove any trailing text after the URL
        path = path.strip().split()[0] if ' ' in path else path.strip()
        documented.add((method.lower(), path))
    
    return documented

def main():
    print("Validating API Documentation...")
    print("=" * 50)
    
    code_endpoints = find_api_endpoints_in_code()
    doc_endpoints = find_documented_endpoints_in_docs()
    
    print(f"Endpoints found in code: {len(code_endpoints)}")
    print(f"Endpoints documented: {len(doc_endpoints)}")
    
    # Check for undocumented endpoints
    undocumented = code_endpoints - doc_endpoints
    if undocumented:
        print("\n⚠️  Undocumented endpoints found in code:")
        for method, path in sorted(undocumented):
            print(f"  {method.upper()} {path}")
    else:
        print("\n✅ All code endpoints are documented!")
    
    # Check for obsolete documentation
    obsolete = doc_endpoints - code_endpoints
    if obsolete:
        print("\n⚠️  Obsolete documented endpoints (no longer in code):")
        for method, path in sorted(obsolete):
            print(f"  {method.upper()} {path}")
    else:
        print("\n✅ All documented endpoints exist in code!")
    
    # Show a summary of all endpoints
    print("\n📋 All documented endpoints:")
    for method, path in sorted(doc_endpoints):
        print(f"  {method.upper()} {path}")

if __name__ == '__main__':
    main()