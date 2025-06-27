# user_auth/test_auth_api.py
import requests
import json
import time

# API base URL
BASE_URL = "http://127.0.0.1:5001/auth"

def test_health():
    """Test health endpoint"""
    print("🔍 Testing health endpoint...")
    try:
        response = requests.get(f"{BASE_URL}/health")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False

def test_registration():
    """Test user registration"""
    print("\n🔍 Testing user registration...")
    
    # Test data
    user_data = {
        "name": "John Doe",
        "email": "john.doe@example.com",
        "company": "Test Company",
        "password": "SecurePass123!",
        "confirmPassword": "SecurePass123!",
        "terms": True
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/register",
            json=user_data,
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"Status: {response.status_code}")
        result = response.json()
        print(f"Response: {json.dumps(result, indent=2)}")
        
        if response.status_code == 200 and result.get('success'):
            print("✅ Registration successful!")
            return result.get('data', {})
        else:
            print(f"❌ Registration failed: {result.get('error')}")
            return None
            
    except Exception as e:
        print(f"❌ Registration test failed: {e}")
        return None

def test_login(email, password):
    """Test user login"""
    print(f"\n🔍 Testing login for {email}...")
    
    login_data = {
        "email": email,
        "password": password,
        "remember": False
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/login",
            json=login_data,
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"Status: {response.status_code}")
        result = response.json()
        print(f"Response: {json.dumps(result, indent=2)}")
        
        if response.status_code == 200 and result.get('success'):
            print("✅ Login successful!")
            return result.get('data', {})
        else:
            print(f"❌ Login failed: {result.get('error')}")
            return None
            
    except Exception as e:
        print(f"❌ Login test failed: {e}")
        return None

def test_invalid_login():
    """Test login with invalid credentials"""
    print("\n🔍 Testing invalid login...")
    
    login_data = {
        "email": "invalid@example.com",
        "password": "wrongpassword",
        "remember": False
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/login",
            json=login_data,
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"Status: {response.status_code}")
        result = response.json()
        
        if response.status_code == 400 and not result.get('success'):
            print("✅ Invalid login correctly rejected!")
            return True
        else:
            print(f"❌ Invalid login test failed: {result}")
            return False
            
    except Exception as e:
        print(f"❌ Invalid login test failed: {e}")
        return False

def test_api_key_validation(api_key):
    """Test API key validation"""
    print(f"\n🔍 Testing API key validation...")
    
    api_data = {
        "api_key": api_key
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/validate-api-key",
            json=api_data,
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"Status: {response.status_code}")
        result = response.json()
        print(f"Response: {json.dumps(result, indent=2)}")
        
        if response.status_code == 200 and result.get('success'):
            print("✅ API key validation successful!")
            return True
        else:
            print(f"❌ API key validation failed: {result.get('error')}")
            return False
            
    except Exception as e:
        print(f"❌ API key validation test failed: {e}")
        return False

def test_user_stats():
    """Test user statistics endpoint"""
    print("\n🔍 Testing user statistics...")
    
    try:
        response = requests.get(f"{BASE_URL}/user-stats")
        
        print(f"Status: {response.status_code}")
        result = response.json()
        print(f"Response: {json.dumps(result, indent=2)}")
        
        if response.status_code == 200 and result.get('success'):
            print("✅ User stats retrieved successfully!")
            return True
        else:
            print(f"❌ User stats failed: {result.get('error')}")
            return False
            
    except Exception as e:
        print(f"❌ User stats test failed: {e}")
        return False

def run_all_tests():
    """Run all authentication tests"""
    print("🚀 Starting FraudShield Authentication API Tests")
    print("=" * 50)
    
    # Test health
    if not test_health():
        print("❌ Health check failed. Make sure the API is running on port 5001")
        return
    
    # Test registration
    registration_result = test_registration()
    if not registration_result:
        print("❌ Registration failed. Cannot continue with other tests.")
        return
    
    # Extract user info
    user_info = registration_result.get('user', {})
    api_key = registration_result.get('api_key')
    email = user_info.get('email')
    
    # Test login with correct credentials
    login_result = test_login(email, "SecurePass123!")
    
    # Test invalid login
    test_invalid_login()
    
    # Test API key validation
    if api_key:
        test_api_key_validation(api_key)
    
    # Test user statistics
    test_user_stats()
    
    print("\n" + "=" * 50)
    print("✅ All tests completed!")
    print("\nTo test manually:")
    print(f"1. Try logging in with: {email} / SecurePass123!")
    print(f"2. Use API key: {api_key}")
    print("3. Access health endpoint: http://127.0.0.1:5001/auth/health")

if __name__ == "__main__":
    run_all_tests()