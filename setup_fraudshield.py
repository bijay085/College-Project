"""
FraudShield Database Setup and Service Manager
Author: FraudShield Team
Location: setup_fraudshield.py
About: Complete setup script for initializing database and starting all services
"""

import os
import sys
import subprocess
import time
import asyncio
import platform
from pathlib import Path

class FraudShieldSetup:
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.services = {}
        self.python_cmd = self.get_python_command()
        
    def get_python_command(self):
        """Get the correct Python command for this system"""
        try:
            # Try python3 first
            subprocess.run([sys.executable, '--version'], check=True, capture_output=True)
            return sys.executable
        except subprocess.CalledProcessError:
            # Fallback to python
            try:
                subprocess.run(['python', '--version'], check=True, capture_output=True)
                return 'python'
            except subprocess.CalledProcessError:
                print("❌ Python not found. Please install Python 3.8+")
                sys.exit(1)

    def print_header(self):
        """Print setup header"""
        print("=" * 60)
        print("🛡️  FraudShield Setup & Service Manager")
        print("=" * 60)
        print(f"📁 Project Root: {self.project_root}")
        print(f"🐍 Python: {self.python_cmd}")
        print(f"💻 Platform: {platform.system()}")
        print()

    def check_dependencies(self):
        """Check if all required dependencies are installed"""
        print("🔍 Checking dependencies...")
        
        required_packages = [
            'motor',
            'pymongo', 
            'flask',
            'flask-cors',
            'bcrypt',
            'python-dotenv',
            'pandas'
        ]
        
        missing_packages = []
        
        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
                print(f"  ✅ {package}")
            except ImportError:
                print(f"  ❌ {package}")
                missing_packages.append(package)
        
        if missing_packages:
            print(f"\n📦 Installing missing packages: {', '.join(missing_packages)}")
            try:
                subprocess.run([
                    self.python_cmd, '-m', 'pip', 'install'
                ] + missing_packages, check=True)
                print("✅ All packages installed successfully")
            except subprocess.CalledProcessError:
                print("❌ Failed to install packages. Please install manually:")
                print(f"   pip install {' '.join(missing_packages)}")
                return False
        
        return True

    def check_mongodb(self):
        """Check if MongoDB is running"""
        print("\n🗄️  Checking MongoDB connection...")
        
        try:
            import pymongo
            client = pymongo.MongoClient('mongodb://localhost:27017', serverSelectionTimeoutMS=3000)
            client.server_info()  # Will raise an exception if not connected
            print("  ✅ MongoDB is running")
            return True
        except Exception as e:
            print(f"  ❌ MongoDB connection failed: {e}")
            print("\n💡 MongoDB Setup Instructions:")
            if platform.system() == "Windows":
                print("  1. Download MongoDB Community from: https://www.mongodb.com/try/download/community")
                print("  2. Install and start MongoDB service")
                print("  3. MongoDB should run on localhost:27017")
            elif platform.system() == "Darwin":  # macOS
                print("  1. Install via Homebrew: brew tap mongodb/brew && brew install mongodb-community")
                print("  2. Start service: brew services start mongodb/brew/mongodb-community")
            else:  # Linux
                print("  1. Install MongoDB: sudo apt-get install -y mongodb")
                print("  2. Start service: sudo systemctl start mongod")
            return False

    async def initialize_database(self):
        """Initialize database collections and seed data"""
        print("\n🔧 Initializing database...")
        
        try:
            # Add project root to Python path
            sys.path.insert(0, str(self.project_root))
            
            # Initialize collections
            from db.init_collections import BlacklistSeeder
            seeder = BlacklistSeeder()
            await seeder.run()
            
            # Initialize rules
            from db.init_rules import RulesSeeder
            rules_seeder = RulesSeeder()
            await rules_seeder.run()
            
            print("✅ Database initialized successfully")
            return True
            
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            return False

    def start_auth_api(self):
        """Start the authentication API service"""
        print("\n🔐 Starting Authentication API...")
        
        auth_script = self.project_root / "user_auth" / "auth_api.py"
        
        if not auth_script.exists():
            print(f"❌ Auth API script not found: {auth_script}")
            return None
        
        try:
            process = subprocess.Popen([
                self.python_cmd, str(auth_script)
            ], cwd=str(self.project_root))
            
            # Give it time to start
            time.sleep(2)
            
            if process.poll() is None:  # Process is still running
                print("  ✅ Authentication API started (Port 5001)")
                return process
            else:
                print("  ❌ Authentication API failed to start")
                return None
                
        except Exception as e:
            print(f"  ❌ Failed to start Auth API: {e}")
            return None

    def start_fraud_api(self):
        """Start the fraud detection API service"""
        print("\n🛡️  Starting Fraud Detection API...")
        
        fraud_script = self.project_root / "logic" / "bulk_api.py"
        
        if not fraud_script.exists():
            print(f"❌ Fraud API script not found: {fraud_script}")
            return None
        
        try:
            process = subprocess.Popen([
                self.python_cmd, str(fraud_script)
            ], cwd=str(self.project_root))
            
            # Give it time to start
            time.sleep(2)
            
            if process.poll() is None:  # Process is still running
                print("  ✅ Fraud Detection API started (Port 5000)")
                return process
            else:
                print("  ❌ Fraud Detection API failed to start")
                return None
                
        except Exception as e:
            print(f"  ❌ Failed to start Fraud API: {e}")
            return None

    def test_apis(self):
        """Test if APIs are responding"""
        print("\n🧪 Testing API endpoints...")
        
        import requests
        
        # Test Auth API
        try:
            response = requests.get('http://127.0.0.1:5001/auth/health'),
        except Exception as e:
            print(f"  ❌ Failed to connect to Auth API: {e}")
            response = None