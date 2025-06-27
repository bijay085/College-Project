/**
 * Enhanced Registration Page JavaScript - Database Integration
 * Author: FraudShield Team
 * Location: user_auth/pages/registration.js
 * About: Complete registration form with real database integration via Python API
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
        this.RETRY_DELAY = 1000; // 1 second
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupPasswordRequirements();
        this.updateProgress();
        this.animateEntrance();
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
            if (input) {
                // Password fields get real-time validation for requirements
                if (field === 'password' || field === 'confirmPassword') {
                    input.addEventListener('input', () => this.handleInput(field, input));
                } else {
                    // Other fields only validate on input if form has been submitted
                    input.addEventListener('input', () => {
                        if (this.formSubmitted) {
                            this.handleInput(field, input);
                        } else {
                            // Just update progress without showing errors
                            this.updateProgress();
                        }
                    });
                }
                
                // Always validate on blur
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

    setupPasswordToggles() {
        const toggles = document.querySelectorAll('.password-toggle');
        toggles.forEach(toggle => {
            toggle.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                
                // Get the input ID from the button's data or find the closest input
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
        // Clear any existing debounce timer
        if (this.debounceTimers[field]) {
            clearTimeout(this.debounceTimers[field]);
        }

        // Password fields get immediate validation for requirements
        if (field === 'password') {
            this.validatePasswordRequirements(input.value);
            // Update confirm password validation if it has a value
            if (this.inputs.confirmPassword.value) {
                this.validateConfirmPassword(this.inputs.confirmPassword.value);
            }
        } else if (field === 'confirmPassword') {
            this.validateConfirmPassword(input.value);
        } else {
            // Other fields use debounced validation
            const delay = field === 'email' ? 500 : 300;
            this.debounceTimers[field] = setTimeout(() => {
                this.validateField(field, input.value);
            }, delay);
        }

        // Update progress immediately for better UX
        this.updateProgress();
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

        // Check for valid name pattern (letters, spaces, hyphens, apostrophes)
        const namePattern = /^[a-zA-Z\s\u00C0-\u017F\u0100-\u024F\u1E00-\u1EFF'-]+$/;
        if (!namePattern.test(trimmed)) {
            this.setFieldState(input, 'error', 'Name can only contain letters, spaces, hyphens, and apostrophes');
            this.validation.name = false;
            return false;
        }

        // Check for at least first and last name
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

        // Check for common disposable email domains
        const disposableDomains = ['tempmail.org', '10minutemail.com', 'guerrillamail.com', 'mailinator.com'];
        const domain = trimmed.split('@')[1];
        if (disposableDomains.includes(domain)) {
            this.setFieldState(input, 'error', 'Temporary email addresses are not allowed');
            this.validation.email = false;
            return false;
        }

        // Check if email already exists (only if form has been submitted or on blur)
        if (this.formSubmitted || event.type === 'blur') {
            try {
                const emailCheckResult = await this.checkEmailExists(trimmed);
                if (emailCheckResult.exists) {
                    this.setFieldState(input, 'error', 'An account with this email already exists');
                    this.validation.email = false;
                    return false;
                }
            } catch (error) {
                console.warn('Email check failed:', error);
                // Continue with validation even if check fails
            }
        }

        this.setFieldState(input, 'valid', 'Valid email address');
        this.validation.email = true;
        return true;
    }

    async checkEmailExists(email) {
        try {
            // For now, we'll skip the email check to avoid complexity
            // In a full implementation, you'd call an API endpoint
            return { exists: false };
        } catch (error) {
            console.warn('Email existence check failed:', error);
            return { exists: false };
        }
    }

    validateCompany(value) {
        const trimmed = value.trim();
        const input = this.inputs.company;

        // Company is optional, so empty is valid
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

        // Allow letters, numbers, spaces, and common business characters
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

        // Calculate and update password strength
        if (value.length > 0) {
            const strength = this.calculatePasswordStrength(value);
            this.updatePasswordStrength(strength);
        } else {
            this.updatePasswordStrength(0);
        }

        // Update internal validation state
        this.validation.password = Object.values(requirements).every(req => req) && value.length > 0;
    }

    validatePassword(value) {
        const input = this.inputs.password;
        
        // Always update requirements in real-time
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

        // Check for common weak patterns
        const weakPatterns = [
            /(.)\1{2,}/, // Repeated characters
            /123456|234567|345678|456789|567890/, // Sequential numbers
            /qwerty|asdfgh|zxcvbn/i, // Keyboard patterns
            /password|admin|user|test|guest/i // Common words
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

        // Re-validate confirm password if it has a value
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
            // Don't show success messages, just style the input
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

    updateProgress() {
        // Check validation status without triggering error messages
        const currentValidation = {
            name: this.inputs.name.value.trim().length >= 2 && this.inputs.name.value.trim().split(/\s+/).length >= 2,
            email: /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(this.inputs.email.value.trim()),
            company: true, // Optional
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
        
        // Mark form as submitted to enable real-time validation
        this.formSubmitted = true;
        
        // Final validation
        if (!this.performFinalValidation()) {
            return;
        }

        this.setLoadingState(true);
        this.hideMessages();

        try {
            // Attempt registration with retry logic
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
            
            // Retry logic for network errors
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

    handleRegistrationSuccess(registrationData) {
        console.log('👤 Registration data:', registrationData);
        
        // Store user data in sessionStorage
        sessionStorage.setItem('fraudshield_user', JSON.stringify(registrationData));
        
        // Store API key securely
        if (registrationData.api_key) {
            sessionStorage.setItem('fraudshield_api_key', registrationData.api_key);
        }
        
        this.showSuccess('Account created successfully!');
        
        // Display API key section
        setTimeout(() => {
            this.displayApiKey(registrationData.api_key);
        }, 1000);
    }

    handleRegistrationError(errorMessage) {
        // Specific error handling
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

        // Validate all fields
        Object.entries(this.inputs).forEach(([field, input]) => {
            if (input && field !== 'terms') {
                const fieldValid = this.validateField(field, input.value);
                if (!fieldValid && !firstInvalidField) {
                    firstInvalidField = input;
                }
                isValid = isValid && fieldValid;
            }
        });

        // Validate terms checkbox
        const termsValid = this.validateField('terms', this.inputs.terms.checked);
        isValid = isValid && termsValid;

        if (!isValid && firstInvalidField) {
            firstInvalidField.focus();
            firstInvalidField.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }

        return isValid;
    }

    async displayApiKey(apiKey) {
        // Hide form and show API key section
        this.form.style.opacity = '0';
        this.form.style.transform = 'translateY(-20px)';
        
        await new Promise(resolve => setTimeout(resolve, 300));
        
        this.form.style.display = 'none';
        this.ui.apiKeyValue.textContent = apiKey;
        this.ui.apiKeyDisplay.classList.remove('hidden');
        
        // Update progress to show completion
        this.ui.progressFill.style.width = '100%';
        this.ui.progressText.textContent = 'Account created successfully!';
        
        // Scroll to API key section
        this.ui.apiKeyDisplay.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    async copyApiKey() {
        const apiKey = this.ui.apiKeyValue.textContent;
        
        try {
            await navigator.clipboard.writeText(apiKey);
            
            // Update button temporarily
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
            // Don't re-enable if form is invalid
            this.updateProgress();
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

    // Static utility methods
    static isLoggedIn() {
        const userData = sessionStorage.getItem('fraudshield_user');
        const apiKey = sessionStorage.getItem('fraudshield_api_key');
        return userData && apiKey;
    }

    static getCurrentUser() {
        const userData = sessionStorage.getItem('fraudshield_user');
        return userData ? JSON.parse(userData) : null;
    }

    static getApiKey() {
        return sessionStorage.getItem('fraudshield_api_key');
    }

    static logout() {
        sessionStorage.removeItem('fraudshield_user');
        sessionStorage.removeItem('fraudshield_api_key');
        localStorage.removeItem('fraudshield_remember');
        localStorage.removeItem('fraudshield_email');
        console.log('👋 User logged out');
    }
}

// Initialize the registration form when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Check if user is already logged in
    if (RegistrationForm.isLoggedIn()) {
        console.log('👤 User already logged in, redirecting...');
        const user = RegistrationForm.getCurrentUser();
        if (user && user.user) {
            // Redirect to appropriate dashboard
            console.log('Redirecting logged-in user...');
            // window.location.href = user.user.role === 'admin' ? '/admin-dashboard.html' : '/index.html';
        }
        return;
    }
    
    window.registrationForm = new RegistrationForm();
    
    // Show development info in console
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        console.log('🔧 Development Mode');
        console.log('📡 Make sure auth API is running: python user_auth/auth_api.py');
        console.log('📊 Make sure MongoDB is running and collections are initialized');
    }
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = RegistrationForm;
}