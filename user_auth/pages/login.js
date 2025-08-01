/**
 * Enhanced Login Page JavaScript - COMPLETE VERSION
 * Author: FraudShield Team
 * Location: user_auth/pages/login.js
 * About: Complete login form with checkout page integration and optimized DB support
 */

class LoginForm {
    constructor() {
        this.form = document.getElementById('loginForm');
        this.inputs = {
            email: document.getElementById('email'),
            password: document.getElementById('password'),
            remember: document.getElementById('remember')
        };
        
        this.ui = {
            submitBtn: document.getElementById('submitBtn'),
            submitText: document.getElementById('submit-text'),
            btnLoader: document.querySelector('.btn-loader'),
            btnContent: document.querySelector('.btn-content'),
            errorMessage: document.getElementById('errorMessage'),
            successMessage: document.getElementById('successMessage')
        };

        this.validation = {
            email: false,
            password: false
        };

        this.debounceTimers = {};
        this.formSubmitted = false;
        
        // API Configuration
        this.API_BASE_URL = 'http://127.0.0.1:5001/auth';
        this.MAX_RETRIES = 3;
        this.RETRY_DELAY = 1000;
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.animateEntrance();
        this.loadRememberedUser();
        this.checkApiConnection();
        this.checkExistingSession();
    }

    /**
     * Enhanced session checking for checkout page compatibility
     */
    async checkExistingSession() {
        try {
            // Check sessionStorage first (checkout page expects these keys)
            let userData = sessionStorage.getItem('fraudshield_user');
            let sessionId = sessionStorage.getItem('fraudshield_session_id');
            let apiKey = sessionStorage.getItem('fraudshield_api_key');
            
            // If not found in sessionStorage, check localStorage for persistent session
            if (!userData || !sessionId) {
                userData = localStorage.getItem('fraudshield_persistent_user');
                sessionId = localStorage.getItem('fraudshield_persistent_session_id');
                apiKey = localStorage.getItem('fraudshield_persistent_api_key');
                
                // Check if persistent session is still valid
                const loginTimestamp = localStorage.getItem('fraudshield_login_timestamp');
                if (loginTimestamp) {
                    const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
                    if (parseInt(loginTimestamp) < thirtyDaysAgo) {
                        console.log('🕐 Persistent session expired, clearing...');
                        this.clearPersistentSession();
                        return;
                    }
                }
            }
            
            if (userData && sessionId) {
                // Validate existing session
                const response = await fetch(`${this.API_BASE_URL}/validate-session`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: sessionId })
                });
                
                if (response.ok) {
                    const result = await response.json();
                    if (result.success) {
                        console.log('✅ Valid existing session found, redirecting...');
                        
                        // Restore session to sessionStorage for checkout page
                        sessionStorage.setItem('fraudshield_user', userData);
                        sessionStorage.setItem('fraudshield_session_id', sessionId);
                        sessionStorage.setItem('fraudshield_api_key', apiKey);
                        
                        this.redirectUser(JSON.parse(userData).user);
                        return;
                    }
                }
                
                // Invalid session, clear all storage
                this.clearSession();
                this.clearPersistentSession();
            }
        } catch (error) {
            console.warn('Session validation failed:', error);
            this.clearSession();
        }
    }

    /**
     * Clear session data
     */
    clearSession() {
        sessionStorage.removeItem('fraudshield_user');
        sessionStorage.removeItem('fraudshield_api_key');
        sessionStorage.removeItem('fraudshield_session_id');
    }

    /**
     * Clear persistent session data
     */
    clearPersistentSession() {
        localStorage.removeItem('fraudshield_persistent_user');
        localStorage.removeItem('fraudshield_persistent_api_key');
        localStorage.removeItem('fraudshield_persistent_session_id');
        localStorage.removeItem('fraudshield_remember');
        localStorage.removeItem('fraudshield_email');
        localStorage.removeItem('fraudshield_login_timestamp');
    }

    async checkApiConnection() {
        try {
            const response = await fetch(`${this.API_BASE_URL}/health`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                console.log('✅ Authentication API connected successfully');
                console.log('📊 Database status:', data.database);
                console.log('🛡️ Fraud API status:', data.fraud_api?.status || 'unknown');
            } else {
                console.warn('⚠️ Authentication API health check failed');
            }
        } catch (error) {
            console.error('❌ Cannot connect to authentication API:', error);
            this.showError('Unable to connect to authentication service. Please try again later.');
        }
    }

    setupEventListeners() {
        // Form submission
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));

        // Real-time validation
        Object.entries(this.inputs).forEach(([field, input]) => {
            if (input && field !== 'remember') {
                input.addEventListener('input', () => {
                    if (this.formSubmitted) {
                        this.handleInput(field, input);
                    }
                });
                
                input.addEventListener('blur', () => this.handleBlur(field, input));
                input.addEventListener('focus', () => this.handleFocus(field, input));
            }
        });

        // Password visibility toggle
        this.setupPasswordToggle();
        
        // Handle Enter key
        Object.values(this.inputs).forEach(input => {
            if (input && input.type !== 'checkbox') {
                input.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        this.handleSubmit(e);
                    }
                });
            }
        });
    }

    setupPasswordToggle() {
        const toggle = document.querySelector('.password-toggle');
        if (toggle) {
            toggle.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                
                const input = this.inputs.password;
                const icon = toggle.querySelector('i');
                
                if (input && icon) {
                    if (input.type === 'password') {
                        input.type = 'text';
                        icon.className = 'fas fa-eye-slash';
                        toggle.setAttribute('aria-label', 'Hide password');
                    } else {
                        input.type = 'password';
                        icon.className = 'fas fa-eye';
                        toggle.setAttribute('aria-label', 'Show password');
                    }
                }
            });
        }
    }

    handleInput(field, input) {
        if (this.debounceTimers[field]) {
            clearTimeout(this.debounceTimers[field]);
        }

        const delay = field === 'email' ? 500 : 300;
        this.debounceTimers[field] = setTimeout(() => {
            this.validateField(field, input.value);
        }, delay);
    }

    handleBlur(field, input) {
        if (this.debounceTimers[field]) {
            clearTimeout(this.debounceTimers[field]);
        }
        this.validateField(field, input.value);
    }

    handleFocus(field, input) {
        this.clearFieldError(input);
    }

    validateField(field, value) {
        switch (field) {
            case 'email':
                return this.validateEmail(value);
            case 'password':
                return this.validatePassword(value);
            default:
                return false;
        }
    }

    validateEmail(value) {
        const trimmed = value.trim().toLowerCase();
        const input = this.inputs.email;

        if (!trimmed) {
            this.setFieldState(input, 'error', 'Email address is required');
            this.validation.email = false;
            return false;
        }

        const emailPattern = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        
        if (!emailPattern.test(trimmed)) {
            this.setFieldState(input, 'error', 'Please enter a valid email address');
            this.validation.email = false;
            return false;
        }

        if (trimmed.length > 254) {
            this.setFieldState(input, 'error', 'Email address is too long');
            this.validation.email = false;
            return false;
        }

        this.setFieldState(input, 'valid');
        this.validation.email = true;
        return true;
    }

    validatePassword(value) {
        const input = this.inputs.password;

        if (!value) {
            this.setFieldState(input, 'error', 'Password is required');
            this.validation.password = false;
            return false;
        }

        if (value.length < 1) {
            this.setFieldState(input, 'error', 'Password cannot be empty');
            this.validation.password = false;
            return false;
        }

        this.setFieldState(input, 'valid');
        this.validation.password = true;
        return true;
    }

    setFieldState(input, state, message) {
        this.clearFieldState(input);
        
        if (state === 'valid') {
            input.classList.add('valid');
        } else if (state === 'error') {
            input.classList.add('invalid');
            if (message) {
                this.setFieldError(input, message);
            }
        }
    }

    clearFieldState(input) {
        input.classList.remove('valid', 'invalid');
        this.clearFieldError(input);
    }

    setFieldError(input, message) {
        this.clearFieldError(input);
        
        const errorElement = document.createElement('div');
        errorElement.className = 'field-error';
        errorElement.textContent = message;
        errorElement.id = `${input.id}-error`;
        
        const formGroup = input.closest('.form-group');
        if (formGroup) {
            formGroup.appendChild(errorElement);
        }
        
        input.setAttribute('aria-describedby', errorElement.id);
    }

    clearFieldError(input) {
        const formGroup = input.closest('.form-group');
        if (formGroup) {
            const existingError = formGroup.querySelector('.field-error');
            if (existingError) {
                existingError.remove();
            }
        }
        
        const ariaDescribedBy = input.getAttribute('aria-describedby');
        if (ariaDescribedBy && ariaDescribedBy.includes('-error')) {
            input.removeAttribute('aria-describedby');
        }
    }

    async handleSubmit(e) {
        e.preventDefault();
        
        this.formSubmitted = true;
        
        if (!this.performFinalValidation()) {
            return;
        }

        this.setLoadingState(true);
        this.hideMessages();

        try {
            const email = this.inputs.email.value.trim();
            const password = this.inputs.password.value;
            const remember = this.inputs.remember.checked;

            const result = await this.attemptLogin(email, password, remember);
            
            if (result.success) {
                this.handleLoginSuccess(result.data, remember);
            } else {
                this.handleLoginError(result.error);
            }
            
        } catch (error) {
            console.error('Login error:', error);
            this.handleLoginError(error.message || 'Login failed. Please try again.');
        } finally {
            this.setLoadingState(false);
        }
    }

    async attemptLogin(email, password, remember, retryCount = 0) {
        try {
            console.log(`🔐 Attempting login for: ${email}`);
            
            const response = await fetch(`${this.API_BASE_URL}/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: email,
                    password: password,
                    remember: remember
                })
            });

            const result = await response.json();
            
            if (response.ok && result.success) {
                console.log('✅ Login successful');
                return { success: true, data: result.data };
            } else {
                const errorMessage = result.error || 'Login failed';
                console.error('❌ Login failed:', errorMessage);
                return { success: false, error: errorMessage };
            }

        } catch (error) {
            console.error('🔌 Network error:', error);
            
            if (retryCount < this.MAX_RETRIES) {
                console.log(`🔄 Retrying login (${retryCount + 1}/${this.MAX_RETRIES})...`);
                await new Promise(resolve => setTimeout(resolve, this.RETRY_DELAY));
                return this.attemptLogin(email, password, remember, retryCount + 1);
            }
            
            return { 
                success: false, 
                error: 'Unable to connect to authentication service. Please check your connection and try again.' 
            };
        }
    }

    /**
     * Enhanced Login Success with checkout page compatibility
     */
    handleLoginSuccess(userData, remember) {
        console.log('👤 User data:', userData);
        
        // Store in format expected by checkout page
        const storage = remember ? localStorage : sessionStorage;
        const storagePrefix = remember ? 'fraudshield_persistent_' : 'fraudshield_';
        
        // Store user data
        storage.setItem(storagePrefix + 'user', JSON.stringify(userData));
        
        // Store API key (checkout page expects this exact key)
        if (userData.api_key) {
            sessionStorage.setItem('fraudshield_api_key', userData.api_key);
            storage.setItem(storagePrefix + 'api_key', userData.api_key);
        }
        
        // Store session ID
        if (userData.session_id) {
            sessionStorage.setItem('fraudshield_session_id', userData.session_id);
            storage.setItem(storagePrefix + 'session_id', userData.session_id);
        }
        
        // CRITICAL: Always store in sessionStorage for checkout compatibility
        sessionStorage.setItem('fraudshield_user', JSON.stringify(userData));
        
        // Remember functionality
        if (remember) {
            localStorage.setItem('fraudshield_remember', 'true');
            localStorage.setItem('fraudshield_email', userData.user.email);
            localStorage.setItem('fraudshield_login_timestamp', Date.now().toString());
        } else {
            this.clearPersistentSession();
        }
        
        this.showSuccess('Login successful! Redirecting...');
        
        // Track successful login
        this.trackLoginEvent(userData.user.email, true);
        
        setTimeout(() => {
            this.redirectUser(userData.user);
        }, 1500);
    }

    /**
     * Track login events for behavioral analysis
     */
    async trackLoginEvent(email, success) {
        try {
            const apiKey = sessionStorage.getItem('fraudshield_api_key');
            if (!apiKey) return;
            
            await fetch(`${this.API_BASE_URL}/track-activity`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${apiKey}`
                },
                body: JSON.stringify({
                    action: 'login',
                    page: 'login',
                    metadata: {
                        success: success,
                        timestamp: new Date().toISOString(),
                        user_agent: navigator.userAgent
                    }
                })
            });
        } catch (error) {
            console.warn('Failed to track login event:', error);
        }
    }

    redirectUser(user) {
        const role = user.role || 'user';
        
        console.log(`🚀 Redirecting ${role} user...`);
        
        // Check for redirect URL in query params
        const urlParams = new URLSearchParams(window.location.search);
        const redirectUrl = urlParams.get('redirect');
        
        if (redirectUrl) {
            try {
                const decodedUrl = decodeURIComponent(redirectUrl);
                if (decodedUrl.startsWith('/') || decodedUrl.startsWith(window.location.origin)) {
                    window.location.href = decodedUrl;
                    return;
                }
            } catch (error) {
                console.warn('Invalid redirect URL:', redirectUrl);
            }
        }
        
        // Default redirects
        if (role === 'admin') {
            this.showSuccess('Welcome Admin! Redirecting to dashboard...');
            setTimeout(() => {
                window.location.href = '/index.html';
            }, 1000);
        } else {
            this.showSuccess('Welcome! Redirecting to dashboard...');
            setTimeout(() => {
                window.location.href = '/index.html';
            }, 1000);
        }
    }

    handleLoginError(errorMessage) {
        if (errorMessage.includes('locked')) {
            this.showError('Account temporarily locked due to too many failed attempts. Please try again later.');
        } else if (errorMessage.includes('Invalid email or password')) {
            this.showError('Invalid email or password. Please check your credentials and try again.');
        } else if (errorMessage.includes('not verified')) {
            this.showError('Please verify your email address before logging in. Check your inbox for a verification link.');
        } else {
            this.showError(errorMessage);
        }
        
        this.inputs.password.value = '';
        this.inputs.password.focus();
        
        // Track failed login
        const email = this.inputs.email.value.trim();
        if (email) {
            this.trackLoginEvent(email, false);
        }
    }

    performFinalValidation() {
        let isValid = true;
        let firstInvalidField = null;

        Object.entries(this.inputs).forEach(([field, input]) => {
            if (input && field !== 'remember') {
                const fieldValid = this.validateField(field, input.value);
                if (!fieldValid && !firstInvalidField) {
                    firstInvalidField = input;
                }
                isValid = isValid && fieldValid;
            }
        });

        if (!isValid && firstInvalidField) {
            firstInvalidField.focus();
            firstInvalidField.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }

        return isValid;
    }

    setLoadingState(loading) {
        if (loading) {
            this.ui.btnContent.classList.add('hidden');
            this.ui.btnLoader.classList.remove('hidden');
            this.ui.submitBtn.disabled = true;
            this.ui.submitBtn.style.cursor = 'not-allowed';
        } else {
            this.ui.btnContent.classList.remove('hidden');
            this.ui.btnLoader.classList.add('hidden');
            this.ui.submitBtn.disabled = false;
            this.ui.submitBtn.style.cursor = 'pointer';
        }
    }

    showError(message) {
        this.ui.errorMessage.querySelector('.alert-text').textContent = message;
        this.ui.errorMessage.classList.remove('hidden');
        this.ui.successMessage.classList.add('hidden');
        this.ui.errorMessage.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        
        setTimeout(() => {
            this.ui.errorMessage.classList.add('hidden');
        }, 10000);
    }

    showSuccess(message) {
        this.ui.successMessage.querySelector('.alert-text').textContent = message;
        this.ui.successMessage.classList.remove('hidden');
        this.ui.errorMessage.classList.add('hidden');
        this.ui.successMessage.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    hideMessages() {
        this.ui.errorMessage.classList.add('hidden');
        this.ui.successMessage.classList.add('hidden');
    }

    loadRememberedUser() {
        if (localStorage.getItem('fraudshield_remember') === 'true') {
            const savedEmail = localStorage.getItem('fraudshield_email');
            if (savedEmail) {
                this.inputs.email.value = savedEmail;
                this.inputs.remember.checked = true;
                this.validateEmail(savedEmail);
                this.inputs.password.focus();
            }
        }
    }

    animateEntrance() {
        const formGroups = document.querySelectorAll('.form-group, .form-options, .submit-btn');
        formGroups.forEach((group, index) => {
            group.style.opacity = '0';
            group.style.transform = 'translateY(20px)';
            
            setTimeout(() => {
                group.style.transition = 'all 0.4s ease-out';
                group.style.opacity = '1';
                group.style.transform = 'translateY(0)';
            }, 100 + (index * 100));
        });
    }

    // Static utility methods for checkout page compatibility
    static isLoggedIn() {
        // Check sessionStorage first (checkout expects this)
        let userData = sessionStorage.getItem('fraudshield_user');
        let apiKey = sessionStorage.getItem('fraudshield_api_key');
        
        if (!userData || !apiKey) {
            userData = localStorage.getItem('fraudshield_persistent_user');
            apiKey = localStorage.getItem('fraudshield_persistent_api_key');
        }
        
        return !!(userData && apiKey);
    }

    static logout() {
        // Clear session storage
        sessionStorage.removeItem('fraudshield_user');
        sessionStorage.removeItem('fraudshield_api_key');
        sessionStorage.removeItem('fraudshield_session_id');
        
        // Clear persistent storage
        localStorage.removeItem('fraudshield_persistent_user');
        localStorage.removeItem('fraudshield_persistent_api_key');
        localStorage.removeItem('fraudshield_persistent_session_id');
        localStorage.removeItem('fraudshield_remember');
        localStorage.removeItem('fraudshield_email');
        localStorage.removeItem('fraudshield_login_timestamp');
        
        // Reset global variables
        window.currentUser = null;
        window.apiKey = null;
        
        console.log('👋 User logged out - all session data cleared');
    }

    static getCurrentUser() {
        // Check sessionStorage first (checkout compatibility)
        let userData = sessionStorage.getItem('fraudshield_user');
        
        if (!userData) {
            userData = localStorage.getItem('fraudshield_persistent_user');
            
            if (userData) {
                sessionStorage.setItem('fraudshield_user', userData);
            }
        }
        
        return userData ? JSON.parse(userData) : null;
    }

    static getApiKey() {
        // Check sessionStorage first (checkout expects this)
        let apiKey = sessionStorage.getItem('fraudshield_api_key');
        
        if (!apiKey) {
            apiKey = localStorage.getItem('fraudshield_persistent_api_key');
            
            if (apiKey) {
                sessionStorage.setItem('fraudshield_api_key', apiKey);
            }
        }
        
        return apiKey;
    }

    static getUserEmail() {
        const userData = this.getCurrentUser();
        return userData?.user?.email || null;
    }

    // Methods for settings page integration
    static async loadUserStats() {
        try {
            const apiKey = this.getApiKey();
            if (!apiKey) {
                throw new Error('No API key found');
            }

            const response = await fetch('http://127.0.0.1:5001/auth/admin/stats', {
                headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`API error: ${response.status}`);
            }

            const data = await response.json();
            if (data.success) {
                const totalUsers = document.getElementById('totalUsers');
                const activeUsers = document.getElementById('activeUsers');
                
                if (totalUsers) totalUsers.textContent = data.data.total_users || 0;
                if (activeUsers) activeUsers.textContent = data.data.active_today || 0;
                
                console.log('✅ User stats loaded successfully');
            }
        } catch (error) {
            console.error('Failed to load user stats:', error);
        }
    }

    static async validateCheckoutKey(apiKey) {
        try {
            const response = await fetch('http://127.0.0.1:5001/auth/validate-checkout-key', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ api_key: apiKey })
            });

            const result = await response.json();
            return result.success && result.data?.valid;
        } catch (error) {
            console.error('Failed to validate checkout key:', error);
            return false;
        }
    }
}

// Initialize the login form when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Check if user is already logged in
    if (LoginForm.isLoggedIn()) {
        console.log('👤 User already appears to be logged in, validating session...');
    }
    
    window.loginForm = new LoginForm();
    
    // Development mode info
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        console.log('🔧 Development Mode - Demo credentials:');
        console.log('Admin: admin@fraudshield.com / Admin@123!');
        console.log('');
        console.log('📡 Make sure auth API is running: python user_auth/auth_api.py');
        console.log('📊 Make sure MongoDB is running with optimized collections');
        console.log('🛡️ Fraud API should be on port 5000, Auth API on port 5001');
    }
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = LoginForm;
}