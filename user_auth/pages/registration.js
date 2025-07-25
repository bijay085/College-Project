/**
 * Enhanced Registration Page JavaScript - COMPLETE VERSION
 * Author: FraudShield Team
 * Location: user_auth/pages/registration.js
 * About: Complete registration form with checkout integration and optimized DB support
 */

class RegistrationForm {
    constructor() {
        this.form = document.getElementById('registrationForm');
        this.inputs = {
            name: document.getElementById('name'),
            email: document.getElementById('email'),
            company: document.getElementById('company'),
            password: document.getElementById('password'),
            confirmPassword: document.getElementById('confirmPassword'),
            terms: document.getElementById('terms')
        };
        
        this.ui = {
            submitBtn: document.getElementById('submitBtn'),
            submitText: document.getElementById('submit-text'),
            btnLoader: document.querySelector('.btn-loader'),
            btnContent: document.querySelector('.btn-content'),
            errorMessage: document.getElementById('errorMessage'),
            successMessage: document.getElementById('successMessage'),
            progressFill: document.getElementById('progressFill'),
            progressText: document.getElementById('progressText'),
            apiKeyDisplay: document.getElementById('apiKeyDisplay'),
            apiKeyValue: document.getElementById('apiKeyValue'),
            copyApiKey: document.getElementById('copyApiKey')
        };

        this.validation = {
            name: false,
            email: false,
            company: true, // Optional field
            password: false,
            confirmPassword: false,
            terms: false
        };

        this.passwordRequirements = {
            length: false,
            uppercase: false,
            lowercase: false,
            number: false,
            special: false
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
        this.setupPasswordRequirements();
        this.updateProgress();
        this.animateEntrance();
        this.checkApiConnection();
        this.checkExistingSession();
    }

    /**
     * Check if user is already logged in
     */
    async checkExistingSession() {
        try {
            // Check for existing session (checkout page compatibility)
            const userData = sessionStorage.getItem('fraudshield_user');
            const apiKey = sessionStorage.getItem('fraudshield_api_key');
            
            if (userData && apiKey) {
                console.log('👤 User already logged in, redirecting...');
                const user = JSON.parse(userData).user;
                
                // Redirect to dashboard
                setTimeout(() => {
                    window.location.href = '/index.html';
                }, 1000);
                
                this.showSuccess('You are already logged in. Redirecting...');
                this.form.style.display = 'none';
            }
        } catch (error) {
            console.warn('Session check failed:', error);
        }
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
            if (input) {
                if (field === 'password' || field === 'confirmPassword') {
                    input.addEventListener('input', () => this.handleInput(field, input));
                } else {
                    input.addEventListener('input', () => {
                        if (this.formSubmitted) {
                            this.handleInput(field, input);
                        } else {
                            this.updateProgress();
                        }
                    });
                }
                
                input.addEventListener('blur', () => this.handleBlur(field, input));
                input.addEventListener('focus', () => this.handleFocus(field, input));
            }
        });

        // Copy API key functionality
        if (this.ui.copyApiKey) {
            this.ui.copyApiKey.addEventListener('click', () => this.copyApiKey());
        }

        // Password visibility toggles
        this.setupPasswordToggles();
        
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

    setupPasswordToggles() {
        const toggles = document.querySelectorAll('.password-toggle');
        toggles.forEach(toggle => {
            toggle.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                
                const inputWrapper = toggle.closest('.input-wrapper');
                const input = inputWrapper ? inputWrapper.querySelector('input[type="password"], input[type="text"]') : null;
                
                if (input) {
                    this.togglePasswordVisibility(input, toggle);
                }
            });
        });
    }

    setupPasswordRequirements() {
        const requirementsContainer = document.getElementById('password-requirements');
        if (requirementsContainer) {
            this.inputs.password.addEventListener('focus', () => {
                requirementsContainer.classList.remove('hidden');
            });
        }
    }

    handleInput(field, input) {
        if (this.debounceTimers[field]) {
            clearTimeout(this.debounceTimers[field]);
        }

        if (field === 'password') {
            this.validatePasswordRequirements(input.value);
            if (this.inputs.confirmPassword.value) {
                this.validateConfirmPassword(this.inputs.confirmPassword.value);
            }
        } else if (field === 'confirmPassword') {
            this.validateConfirmPassword(input.value);
        } else {
            const delay = field === 'email' ? 500 : 300;
            this.debounceTimers[field] = setTimeout(() => {
                this.validateField(field, input.value);
            }, delay);
        }

        this.updateProgress();
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
            case 'name':
                return this.validateName(value);
            case 'email':
                return this.validateEmail(value);
            case 'company':
                return this.validateCompany(value);
            case 'password':
                return this.validatePassword(value);
            case 'confirmPassword':
                return this.validateConfirmPassword(value);
            case 'terms':
                return this.validateTerms(value);
            default:
                return false;
        }
    }

    validateName(value) {
        const trimmed = value.trim();
        const input = this.inputs.name;

        if (!trimmed) {
            this.setFieldState(input, 'error', 'Full name is required');
            this.validation.name = false;
            return false;
        }

        if (trimmed.length < 2) {
            this.setFieldState(input, 'error', 'Name must be at least 2 characters');
            this.validation.name = false;
            return false;
        }

        if (trimmed.length > 100) {
            this.setFieldState(input, 'error', 'Name is too long');
            this.validation.name = false;
            return false;
        }

        const namePattern = /^[a-zA-Z\s\u00C0-\u017F\u0100-\u024F\u1E00-\u1EFF'-]+$/;
        if (!namePattern.test(trimmed)) {
            this.setFieldState(input, 'error', 'Name can only contain letters, spaces, hyphens, and apostrophes');
            this.validation.name = false;
            return false;
        }

        const nameParts = trimmed.split(/\s+/);
        if (nameParts.length < 2) {
            this.setFieldState(input, 'error', 'Please enter your full name (first and last)');
            this.validation.name = false;
            return false;
        }

        this.setFieldState(input, 'valid', 'Looks good!');
        this.validation.name = true;
        return true;
    }

    async validateEmail(value) {
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

        // Check for common disposable email domains
        const disposableDomains = ['tempmail.org', '10minutemail.com', 'guerrillamail.com', 'mailinator.com'];
        const domain = trimmed.split('@')[1];
        if (disposableDomains.includes(domain)) {
            this.setFieldState(input, 'error', 'Temporary email addresses are not allowed');
            this.validation.email = false;
            return false;
        }

        this.setFieldState(input, 'valid', 'Valid email address');
        this.validation.email = true;
        return true;
    }

    validateCompany(value) {
        const trimmed = value.trim();
        const input = this.inputs.company;

        if (!trimmed) {
            this.clearFieldState(input);
            this.validation.company = true;
            return true;
        }

        if (trimmed.length < 2) {
            this.setFieldState(input, 'error', 'Company name must be at least 2 characters');
            this.validation.company = false;
            return false;
        }

        if (trimmed.length > 100) {
            this.setFieldState(input, 'error', 'Company name is too long');
            this.validation.company = false;
            return false;
        }

        const companyPattern = /^[a-zA-Z0-9\s\u00C0-\u017F\u0100-\u024F\u1E00-\u1EFF&.,'-]+$/;
        if (!companyPattern.test(trimmed)) {
            this.setFieldState(input, 'error', 'Company name contains invalid characters');
            this.validation.company = false;
            return false;
        }

        this.setFieldState(input, 'valid', 'Valid company name');
        this.validation.company = true;
        return true;
    }

    validatePasswordRequirements(value) {
        const requirements = {
            length: value.length >= 8,
            uppercase: /[A-Z]/.test(value),
            lowercase: /[a-z]/.test(value),
            number: /[0-9]/.test(value),
            special: /[!@#$%^&*()_+\-=\[\]{}|;':".,<>?]/.test(value)
        };

        this.passwordRequirements = requirements;
        this.updatePasswordRequirements();

        if (value.length > 0) {
            const strength = this.calculatePasswordStrength(value);
            this.updatePasswordStrength(strength);
        } else {
            this.updatePasswordStrength(0);
        }

        this.validation.password = Object.values(requirements).every(req => req) && value.length > 0;
    }

    validatePassword(value) {
        const input = this.inputs.password;
        
        this.validatePasswordRequirements(value);

        if (!value) {
            this.setFieldState(input, 'error', 'Password is required');
            this.validation.password = false;
            return false;
        }

        if (value.length > 128) {
            this.setFieldState(input, 'error', 'Password is too long');
            this.validation.password = false;
            return false;
        }

        const weakPatterns = [
            /(.)\1{2,}/,
            /123456|234567|345678|456789|567890/,
            /qwerty|asdfgh|zxcvbn/i,
            /password|admin|user|test|guest/i
        ];

        if (weakPatterns.some(pattern => pattern.test(value))) {
            this.setFieldState(input, 'error', 'Password contains common patterns. Please choose a more secure password.');
            this.validation.password = false;
            return false;
        }

        const allRequirementsMet = Object.values(this.passwordRequirements).every(req => req);
        
        if (!allRequirementsMet) {
            const missing = Object.entries(this.passwordRequirements)
                .filter(([key, met]) => !met)
                .map(([key]) => this.getRequirementText(key))
                .join(', ');
            
            this.setFieldState(input, 'error', `Password must include: ${missing}`);
            this.validation.password = false;
            return false;
        }

        this.setFieldState(input, 'valid', 'Strong password');
        this.validation.password = true;

        if (this.inputs.confirmPassword.value) {
            this.validateConfirmPassword(this.inputs.confirmPassword.value);
        }

        return true;
    }

    validateConfirmPassword(value) {
        const input = this.inputs.confirmPassword;
        const passwordValue = this.inputs.password.value;

        if (!value) {
            this.setFieldState(input, 'error', 'Please confirm your password');
            this.validation.confirmPassword = false;
            return false;
        }

        if (value !== passwordValue) {
            this.setFieldState(input, 'error', 'Passwords do not match');
            this.validation.confirmPassword = false;
            return false;
        }

        this.setFieldState(input, 'valid', 'Passwords match');
        this.validation.confirmPassword = true;
        return true;
    }

    validateTerms(checked) {
        const input = this.inputs.terms;
        
        if (!checked) {
            this.setFieldError(input, 'You must agree to the Terms of Service and Privacy Policy');
            this.validation.terms = false;
            return false;
        }

        this.clearFieldError(input);
        this.validation.terms = true;
        return true;
    }

    getRequirementText(requirement) {
        const texts = {
            length: 'at least 8 characters',
            uppercase: 'one uppercase letter',
            lowercase: 'one lowercase letter',
            number: 'one number',
            special: 'one special character'
        };
        return texts[requirement] || requirement;
    }

    calculatePasswordStrength(password) {
        let score = 0;
        const checks = {
            length: password.length >= 8 ? 20 : 0,
            lengthBonus: password.length >= 12 ? 10 : 0,
            uppercase: /[A-Z]/.test(password) ? 15 : 0,
            lowercase: /[a-z]/.test(password) ? 15 : 0,
            numbers: /[0-9]/.test(password) ? 15 : 0,
            special: /[!@#$%^&*()_+\-=\[\]{}|;':".,<>?]/.test(password) ? 15 : 0,
            variety: new Set(password).size >= 8 ? 10 : 0
        };

        score = Object.values(checks).reduce((sum, points) => sum + points, 0);
        return Math.min(100, score);
    }

    updatePasswordRequirements() {
        Object.entries(this.passwordRequirements).forEach(([requirement, met]) => {
            const element = document.querySelector(`[data-requirement="${requirement}"]`);
            if (element) {
                element.classList.toggle('met', met);
            }
        });
    }

    updatePasswordStrength(strength) {
        const strengthFill = document.getElementById('strengthFill');
        const strengthLabel = document.getElementById('strengthLabel');
        
        if (!strengthFill || !strengthLabel) return;

        let level = 'weak';
        let text = 'Weak';
        
        if (strength >= 80) {
            level = 'strong';
            text = 'Strong';
        } else if (strength >= 60) {
            level = 'good';
            text = 'Good';
        } else if (strength >= 40) {
            level = 'fair';
            text = 'Fair';
        }

        strengthFill.className = `strength-fill ${level}`;
        strengthLabel.textContent = text;
    }

    setFieldState(input, state, message) {
        this.clearFieldState(input);
        
        if (state === 'valid') {
            input.classList.add('valid');
        } else if (state === 'error') {
            input.classList.add('invalid');
            this.setFieldError(input, message);
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

    updateProgress() {
        const currentValidation = {
            name: this.inputs.name.value.trim().length >= 2 && this.inputs.name.value.trim().split(/\s+/).length >= 2,
            email: /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(this.inputs.email.value.trim()),
            company: true,
            password: this.inputs.password.value.length >= 8 && Object.values(this.passwordRequirements).every(req => req),
            confirmPassword: this.inputs.confirmPassword.value === this.inputs.password.value && this.inputs.confirmPassword.value.length > 0,
            terms: this.inputs.terms.checked
        };

        const validFields = Object.values(currentValidation).filter(Boolean).length;
        const totalFields = Object.keys(currentValidation).length;
        const progress = (validFields / totalFields) * 100;
        
        this.ui.progressFill.style.width = `${progress}%`;
        
        if (progress === 100) {
            this.ui.progressText.textContent = 'Step 2 of 2: Ready to create account';
            this.ui.submitBtn.disabled = false;
        } else {
            this.ui.progressText.textContent = 'Step 1 of 2: Complete all fields';
            this.ui.submitBtn.disabled = true;
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
            const result = await this.attemptRegistration();
            
            if (result.success) {
                this.handleRegistrationSuccess(result.data);
            } else {
                this.handleRegistrationError(result.error);
            }
            
        } catch (error) {
            console.error('Registration error:', error);
            this.handleRegistrationError(error.message || 'Registration failed. Please try again.');
        } finally {
            this.setLoadingState(false);
        }
    }

    async attemptRegistration(retryCount = 0) {
        try {
            const formData = {
                name: this.inputs.name.value.trim(),
                email: this.inputs.email.value.trim().toLowerCase(),
                company: this.inputs.company.value.trim() || null,
                password: this.inputs.password.value,
                confirmPassword: this.inputs.confirmPassword.value,
                terms: this.inputs.terms.checked
            };

            console.log('🚀 Attempting registration for:', formData.email);
            
            const response = await fetch(`${this.API_BASE_URL}/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            });

            const result = await response.json();
            
            if (response.ok && result.success) {
                console.log('✅ Registration successful');
                return { success: true, data: result.data };
            } else {
                const errorMessage = result.error || 'Registration failed';
                console.error('❌ Registration failed:', errorMessage);
                return { success: false, error: errorMessage };
            }

        } catch (error) {
            console.error('🔌 Network error:', error);
            
            if (retryCount < this.MAX_RETRIES) {
                console.log(`🔄 Retrying registration (${retryCount + 1}/${this.MAX_RETRIES})...`);
                await new Promise(resolve => setTimeout(resolve, this.RETRY_DELAY));
                return this.attemptRegistration(retryCount + 1);
            }
            
            return { 
                success: false, 
                error: 'Unable to connect to authentication service. Please check your connection and try again.' 
            };
        }
    }

    /**
     * Handle successful registration - checkout page compatible
     */
    handleRegistrationSuccess(registrationData) {
        console.log('👤 Registration data:', registrationData);
        
        // Store user data in sessionStorage (checkout expects this)
        sessionStorage.setItem('fraudshield_user', JSON.stringify(registrationData));
        
        // Store API key (checkout page expects this exact key)
        if (registrationData.api_key) {
            sessionStorage.setItem('fraudshield_api_key', registrationData.api_key);
        }
        
        // Store session ID if provided
        if (registrationData.session_id) {
            sessionStorage.setItem('fraudshield_session_id', registrationData.session_id);
        }
        
        this.showSuccess('Account created successfully!');
        
        // Track registration event
        this.trackRegistrationEvent(registrationData.user.email);
        
        // Display API key section
        setTimeout(() => {
            this.displayApiKey(registrationData.api_key);
        }, 1000);
    }

    /**
     * Track registration for analytics
     */
    async trackRegistrationEvent(email) {
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
                    action: 'registration',
                    page: 'registration',
                    metadata: {
                        email: email,
                        timestamp: new Date().toISOString(),
                        user_agent: navigator.userAgent
                    }
                })
            });
        } catch (error) {
            console.warn('Failed to track registration event:', error);
        }
    }

    handleRegistrationError(errorMessage) {
        if (errorMessage.includes('already exists')) {
            this.showError('An account with this email already exists. Please use a different email or try logging in.');
            this.inputs.email.focus();
        } else if (errorMessage.includes('weak')) {
            this.showError('Password is too weak. Please choose a stronger password.');
            this.inputs.password.focus();
        } else if (errorMessage.includes('terms')) {
            this.showError('You must agree to the Terms of Service and Privacy Policy to create an account.');
        } else {
            this.showError(errorMessage);
        }
    }

    performFinalValidation() {
        let isValid = true;
        let firstInvalidField = null;

        Object.entries(this.inputs).forEach(([field, input]) => {
            if (input && field !== 'terms') {
                const fieldValid = this.validateField(field, input.value);
                if (!fieldValid && !firstInvalidField) {
                    firstInvalidField = input;
                }
                isValid = isValid && fieldValid;
            }
        });

        const termsValid = this.validateField('terms', this.inputs.terms.checked);
        isValid = isValid && termsValid;

        if (!isValid && firstInvalidField) {
            firstInvalidField.focus();
            firstInvalidField.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }

        return isValid;
    }

    async displayApiKey(apiKey) {
        this.form.style.opacity = '0';
        this.form.style.transform = 'translateY(-20px)';
        
        await new Promise(resolve => setTimeout(resolve, 300));
        
        this.form.style.display = 'none';
        this.ui.apiKeyValue.textContent = apiKey;
        this.ui.apiKeyDisplay.classList.remove('hidden');
        
        this.ui.progressFill.style.width = '100%';
        this.ui.progressText.textContent = 'Account created successfully!';
        
        this.ui.apiKeyDisplay.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    async copyApiKey() {
        const apiKey = this.ui.apiKeyValue.textContent;
        
        try {
            await navigator.clipboard.writeText(apiKey);
            
            const originalContent = this.ui.copyApiKey.innerHTML;
            this.ui.copyApiKey.innerHTML = '<i class="fas fa-check"></i> Copied!';
            this.ui.copyApiKey.style.background = 'var(--success-600)';
            
            setTimeout(() => {
                this.ui.copyApiKey.innerHTML = originalContent;
                this.ui.copyApiKey.style.background = '';
            }, 2000);
            
        } catch (error) {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = apiKey;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            
            this.ui.copyApiKey.innerHTML = '<i class="fas fa-check"></i> Copied!';
            setTimeout(() => {
                this.ui.copyApiKey.innerHTML = '<i class="fas fa-copy"></i> Copy';
            }, 2000);
        }
    }

    togglePasswordVisibility(input, toggle) {
        const eyeIcon = toggle.querySelector('i');
        
        if (input && eyeIcon) {
            if (input.type === 'password') {
                input.type = 'text';
                eyeIcon.className = 'fas fa-eye-slash';
                toggle.setAttribute('aria-label', 'Hide password');
            } else {
                input.type = 'password';
                eyeIcon.className = 'fas fa-eye';
                toggle.setAttribute('aria-label', 'Show password');
            }
        }
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
            this.updateProgress();
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

    animateEntrance() {
        const formGroups = document.querySelectorAll('.form-group');
        formGroups.forEach((group, index) => {
            group.style.opacity = '0';
            group.style.transform = 'translateY(20px)';
            
            setTimeout(() => {
                group.style.transition = 'all 0.4s ease-out';
                group.style.opacity = '1';
                group.style.transform = 'translateY(0)';
            }, 100 + (index * 50));
        });
    }

    // Static utility methods for checkout compatibility
    static isLoggedIn() {
        const userData = sessionStorage.getItem('fraudshield_user');
        const apiKey = sessionStorage.getItem('fraudshield_api_key');
        return !!(userData && apiKey);
    }

    static getCurrentUser() {
        const userData = sessionStorage.getItem('fraudshield_user');
        return userData ? JSON.parse(userData) : null;
    }

    static getApiKey() {
        return sessionStorage.getItem('fraudshield_api_key');
    }

    static getUserEmail() {
        const userData = this.getCurrentUser();
        return userData?.user?.email || null;
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
        
        console.log('👋 User logged out');
    }
}

// Initialize the registration form when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Check if user is already logged in
    if (RegistrationForm.isLoggedIn()) {
        console.log('👤 User already logged in, checking session...');
        const user = RegistrationForm.getCurrentUser();
        if (user && user.user) {
            console.log('Redirecting logged-in user...');
        }
    }
    
    window.registrationForm = new RegistrationForm();
    
    // Development mode info
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        console.log('🔧 Development Mode');
        console.log('📡 Make sure auth API is running: python user_auth/auth_api.py');
        console.log('📊 Make sure MongoDB is running with optimized collections');
        console.log('🛡️ Fraud API should be on port 5000, Auth API on port 5001');
    }
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = RegistrationForm;
}