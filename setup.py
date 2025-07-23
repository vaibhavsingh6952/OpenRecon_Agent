import os
import sys
import subprocess
import importlib.util

def check_python_version():
    if sys.version_info < (3, 8):
        print("Python 3.8 or higher is required.")
        print(f"   Current version: {sys.version}")
        return False
    
    print(f"Python version: {sys.version}")
    return True

def install_requirements():
    print("\nInstalling required packages...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("All packages installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to install packages: {e}")
        return False

def check_package(package_name):
    spec = importlib.util.find_spec(package_name)
    return spec is not None

def verify_installation():
    print("\nVerifying installation...")
    required_packages = [
        "streamlit", "cohere", "shodan", "vt", "abuseipdb_wrapper", 
        "requests", "dotenv", "packaging"
    ]
    
    all_installed = True
    for package in required_packages:
        # Handle special case for python-dotenv
        package_check = "dotenv" if package == "dotenv" else package
        if check_package(package_check):
            print(f"OK: {package}")
        else:
            print(f"MISSING: {package}")
            all_installed = False
    
    return all_installed

def test_agent_imports():
    print("\nTesting AI Agent imports...")
    try:
        from aiagent import identify_target_type, OSINT_TOOLS
        print("Agent core imports successful")
        print(f"{len(OSINT_TOOLS)} OSINT tools available")
        
        # Test basic functionality
        test_result = identify_target_type("8.8.8.8")
        if test_result == "ip":
            print("Agent target identification working")
        else:
            print("Agent target identification failed")
            return False
            
        return True
    except Exception as e:
        print(f"Agent import failed: {e}")
        return False

def create_env_template():
    env_example = ".env.example"
    env_template = """# AI OSINT Security Analyzer Environment Configuration

# AI-Powered Autonomous OSINT Analyzer using Cohere Tool Use Framework

# Instructions:
# 1. Copy this file to .env
# 2. Replace the placeholder values with your actual API keys
# 3. Keep your .env file secure and never commit it to version control


# AI AGENT - Required for autonomous operation

# Cohere API Key (Required for AI Agent)
# Get your key from: https://dashboard.cohere.ai/api-keys
# Free tier: Available - check current limits at https://cohere.com/pricing
COHERE_API_KEY=your_cohere_api_key_here


# OSINT TOOL APIs - Configure based on your analysis needs

# Shodan API Key
# Get your key from: https://account.shodan.io/
# Free tier: 100 queries/month
SHODAN_API_KEY=your_shodan_api_key_here

# VirusTotal API Key
# Get your key from: https://www.virustotal.com/gui/join-us
# Free tier: 500 queries/day
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# AbuseIPDB API Key
# Get your key from: https://www.abuseipdb.com/api
# Free tier: 1,000 queries/day
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here


# NOTES

# No API keys required for:
# - CVE-Search (Free vulnerability intelligence)
# - CISA KEV (Government exploit database)
# - NVD (Official CVE repository)

"""
    
    if not os.path.exists(env_example):
        try:
            with open(env_example, "w") as f:
                f.write(env_template)
            print(f"Created {env_example}")
        except Exception as e:
            print(f"Failed to create environment template: {e}")
    else:
        print(f"{env_example} already exists")

def display_api_info():
    print("\nAPI Key Setup Information:")
    print("=" * 50)
    
    apis = [
        ("Cohere (AI Agent)", "https://dashboard.cohere.ai/api-keys", "Free tier available", "Required"),
        ("Shodan", "https://account.shodan.io/", "100 queries/month", "Network recon"),
        ("VirusTotal", "https://www.virustotal.com/gui/join-us", "500 queries/day", "Threat intel"),
        ("AbuseIPDB", "https://www.abuseipdb.com/api", "1,000 queries/day", "IP reputation")
    ]
    
    for name, url, limit, purpose in apis:
        print(f"{name}: {url}")
        print(f"   Free tier: {limit} | Purpose: {purpose}")
        print()

def main():
    print("AI OSINT Security Analyzer Setup")
    print("   AI-Powered Autonomous OSINT Analyzer")
    print("   Powered by Cohere Tool Use Framework")
    print("=" * 60)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        sys.exit(1)
    
    # Verify installation
    if not verify_installation():
        print("\nSome packages failed to install. Please check the errors above.")
        sys.exit(1)
    
    # Test agent imports
    if not test_agent_imports():
        print("\nAgent functionality test failed. Please check the installation.")
        sys.exit(1)
    
    # Create environment template
    create_env_template()
    
    # Display API information
    display_api_info()
    
    print("Setup completed successfully!")
    print("\nNext steps:")
    print("1. Copy .env.example to .env")
    print("2. Add your API keys to the .env file")
    print("3. Run: streamlit run app.py")
    print("\nSee README.md for detailed setup instructions")
    print("The AI agent will autonomously select and execute OSINT tools!")

if __name__ == "__main__":
    main() 