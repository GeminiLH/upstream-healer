#!/usr/bin/env python3
"""
Simple test runner for API documentation tests
"""
import subprocess
import sys
import os

def run_tests():
    """Run all API-related tests"""
    print("Running Upstream Healer API Tests...")
    print("=" * 50)
    
    # Change to project root directory
    project_root = "/mnt/Aquaman/upstream-healer"
    os.chdir(project_root)
    
    try:
        # Run pytest on the API test file
        result = subprocess.run([
            sys.executable, "-m", "pytest", 
            "tests/test_api_endpoints.py", 
            "-v", 
            "--tb=short"
        ], capture_output=True, text=True)
        
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
            
        print(f"Return code: {result.returncode}")
        
        if result.returncode == 0:
            print("\n✅ All tests passed!")
        else:
            print("\n❌ Some tests failed!")
            
        return result.returncode
        
    except Exception as e:
        print(f"Error running tests: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(run_tests())