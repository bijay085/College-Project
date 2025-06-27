/**
 * Enhanced Login Page JavaScript - Database Integration - FIXED VERSION
 * Author: FraudShield Team
 * Location: user_auth/pages/login.js
 * About: Complete login form with real database authentication via Python API
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
        this.RETRY_DELAY = 1000; // 1 second
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.animateEntrance();
        this.loadRememberedUser();
        this.checkApiConnection();
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
                console.log('✅ Authentication API connected successfully');
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

        // Real-time validation - only show errors after blur or form submission
        Object.entries(this.inputs).forEach(([field, input]) => {
            if (input && field !== 'remember') {
                // Only validate on input if form has been submitted
                input.addEventListener('input', () => {
                    if (this.formSubmitted) {
                        this.handleInput(field, input);
                    }
                });
                
                // Always validate on blur
                input.addEventListener('blur', () => this.handleBlur(field, input));
                input.addEventListener('focus', () => this.handleFocus(field, input));
            }
        });

        // Password visibility toggle
        this.setupPasswordToggle();
        
        // Handle Enter key in inputs
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
        // Clear any existing debounce timer
        if (this.debounceTimers[field]) {
            clearTimeout(this.debounceTimers[field]);
        }

        // Debounce validation for better performance
        const delay = field === 'email' ? 500 : 300;
        this.debounceTimers[field] = setTimeout(() => {
            this.validateField(field, input.value);
        }, delay);
    }

    handleBlur(field, input) {
        // Clear debounce timer and validate immediately on blur
        if (this.debounceTimers[field]) {
            clearTimeout(this.debounceTimers[field]);
        }
        this.validateField(field, input.value);
    }

    handleFocus(field, input) {
        // Clear any error states when user focuses
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

        // RFC 5322 compliant email regex (simplified)
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
        
        // Add error message after the input's parent wrapper
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
        
        // Remove aria-describedby for error
        const ariaDescribedBy = input.getAttribute('aria-describedby');
        if (ariaDescribedBy && ariaDescribedBy.includes('-error')) {
            input.removeAttribute('aria-describedby');
        }
    }

    async handleSubmit(e) {
        e.preventDefault();
        
        // Mark form as submitted to enable real-time validation
        this.formSubmitted = true;
        
        // Final validation
        if (!this.performFinalValidation()) {
            return;
        }

        this.setLoadingState(true);
        this.hideMessages();

        try {
            const email = this.inputs.email.value.trim();
            const password = this.inputs.password.value;
            const remember = this.inputs.remember.checked;

            // Attempt login with retry logic
            const result = await this.attemptLogin(email, password, remember);
            
            if (result.success) {
                this.handleLoginSuccess(result.data, remember);
                // ✅ FIXED: Removed hardcoded redirect - let handleLoginSuccess handle it
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
            
            // Retry logic for network errors
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

    handleLoginSuccess(userData, remember) {
        console.log('👤 User data:', userData);
        
        // Store user data in sessionStorage
        sessionStorage.setItem('fraudshield_user', JSON.stringify(userData));
        
        // Store API key securely
        if (userData.api_key) {
            sessionStorage.setItem('fraudshield_api_key', userData.api_key);
        }
        
        // Handle remember me functionality
        if (remember) {
            localStorage.setItem('fraudshield_remember', 'true');
            localStorage.setItem('fraudshield_email', userData.user.email);
        } else {
            localStorage.removeItem('fraudshield_remember');
            localStorage.removeItem('fraudshield_email');
        }
        
        this.showSuccess('Login successful! Redirecting...');
        
        // ✅ FIXED: Redirect based on user role with proper timing
        setTimeout(() => {
            this.redirectUser(userData.user);
        }, 1500);
    }

    redirectUser(user) {
        const role = user.role || 'user';
        
        console.log(`🚀 Redirecting ${role} user...`);
        
        // ✅ FIXED: Actually redirect based on role
        if (role === 'admin') {
            this.showSuccess('Welcome Admin! Redirecting to admin dashboard...');
            setTimeout(() => {
                window.location.href = '/index.html';
            }, 1000);
        } else {
            this.showSuccess('Welcome! Redirecting to dashboard...');
            setTimeout(() => {
                window.location.href = '/index.html'; // Main dashboard for regular users
            }, 1000);
        }
    }

    getRedirectUrl(role) {
        const redirectUrls = {
            'admin': '/admin-dashboard.html',
            'user': '/index.html',
            'moderator': '/moderator-dashboard.html'
        };
        
        return redirectUrls[role] || '/index.html';
    }

    handleLoginError(errorMessage) {
        // Specific error handling
        if (errorMessage.includes('locked')) {
            this.showError('Account temporarily locked due to too many failed attempts. Please try again later.');
        } else if (errorMessage.includes('Invalid email or password')) {
            this.showError('Invalid email or password. Please check your credentials and try again.');
        } else if (errorMessage.includes('not verified')) {
            this.showError('Please verify your email address before logging in. Check your inbox for a verification link.');
        } else {
            this.showError(errorMessage);
        }
        
        // Clear password field on error
        this.inputs.password.value = '';
        this.inputs.password.focus();
    }

    performFinalValidation() {
        let isValid = true;
        let firstInvalidField = null;

        // Validate all fields
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
        
        // Auto-hide error after 10 seconds
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
        // Check if user wants to be remembered
        if (localStorage.getItem('fraudshield_remember') === 'true') {
            const savedEmail = localStorage.getItem('fraudshield_email');
            if (savedEmail) {
                this.inputs.email.value = savedEmail;
                this.inputs.remember.checked = true;
                // Validate the pre-filled email
                this.validateEmail(savedEmail);
                // Focus on password field
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

    // Utility method to check if user is already logged in
    static isLoggedIn() {
        const userData = sessionStorage.getItem('fraudshield_user');
        const apiKey = sessionStorage.getItem('fraudshield_api_key');
        return userData && apiKey;
    }

    // Utility method to logout user
    static logout() {
        sessionStorage.removeItem('fraudshield_user');
        sessionStorage.removeItem('fraudshield_api_key');
        localStorage.removeItem('fraudshield_remember');
        localStorage.removeItem('fraudshield_email');
        console.log('👋 User logged out');
    }

    // Utility method to get current user
    static getCurrentUser() {
        const userData = sessionStorage.getItem('fraudshield_user');
        return userData ? JSON.parse(userData) : null;
    }

    // Utility method to get API key
    static getApiKey() {
        return sessionStorage.getItem('fraudshield_api_key');
    }
}

// Initialize the login form when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Check if user is already logged in
    if (LoginForm.isLoggedIn()) {
        console.log('👤 User already logged in, redirecting...');
        const user = LoginForm.getCurrentUser();
        if (user && user.user) {
            // Redirect to appropriate dashboard based on role
            const role = user.user.role || 'user';
            if (role === 'admin') {
                window.location.href = '/admin-dashboard.html';
            } else {
                window.location.href = '/index.html';
            }
        }
        return;
    }
    
    window.loginForm = new LoginForm();
    
    // Show demo credentials hint in console for development
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        console.log('🔧 Development Mode - Demo credentials:');
        console.log('Admin: admin@fraudshield.com / Admin@123!');
        console.log('User: user@example.com / User@123!');
        console.log('');
        console.log('📡 Make sure auth API is running: python user_auth/auth_api.py');
    }
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = LoginForm;
}