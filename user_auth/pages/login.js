/**
 * Login Page JavaScript - Enhanced Validation & UX
 * Author: FraudShield Team
 * Location: user_auth/pages/login.js
 * About: Modern login form with real-time validation and clean UI interactions
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
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.animateEntrance();
        this.clearInputs();
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

            // Simulate API call
            await this.simulateLogin(email, password, remember);
            
        } catch (error) {
            console.error('Login error:', error);
            this.showError(error.message || 'Login failed. Please try again.');
        } finally {
            this.setLoadingState(false);
        }
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

    async simulateLogin(email, password, remember) {
        // Simulate network delay
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        // Demo credentials for testing
        const testCredentials = [
            { email: 'admin@fraudshield.com', password: 'admin123', role: 'admin' },
            { email: 'user@fraudshield.com', password: 'user123', role: 'user' },
            { email: 'demo@fraudshield.com', password: 'demo123', role: 'user' }
        ];

        const user = testCredentials.find(cred => 
            cred.email === email.toLowerCase() && cred.password === password
        );

        if (user) {
            this.showSuccess('Login successful! Redirecting to dashboard...');
            
            // Store login state if remember me is checked
            if (remember) {
                localStorage.setItem('fraudshield_remember', 'true');
                localStorage.setItem('fraudshield_email', email);
            }
            
            // Simulate redirect
            setTimeout(() => {
                if (user.role === 'admin') {
                    // window.location.href = '/admin-dashboard';
                    this.showSuccess('Redirecting to Admin Dashboard...');
                } else {
                    // window.location.href = '/dashboard';
                    this.showSuccess('Redirecting to User Dashboard...');
                }
            }, 2000);
        } else {
            throw new Error('Invalid email or password. Please try again.');
        }
    }

    setLoadingState(loading) {
        if (loading) {
            this.ui.btnContent.classList.add('hidden');
            this.ui.btnLoader.classList.remove('hidden');
            this.ui.submitBtn.disabled = true;
        } else {
            this.ui.btnContent.classList.remove('hidden');
            this.ui.btnLoader.classList.add('hidden');
            this.ui.submitBtn.disabled = false;
        }
    }

    showError(message) {
        this.ui.errorMessage.querySelector('.alert-text').textContent = message;
        this.ui.errorMessage.classList.remove('hidden');
        this.ui.successMessage.classList.add('hidden');
        this.ui.errorMessage.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
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

    clearInputs() {
        // Clear form inputs on page load
        this.inputs.email.value = '';
        this.inputs.password.value = '';
        
        // Check if user wants to be remembered
        if (localStorage.getItem('fraudshield_remember') === 'true') {
            const savedEmail = localStorage.getItem('fraudshield_email');
            if (savedEmail) {
                this.inputs.email.value = savedEmail;
                this.inputs.remember.checked = true;
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
}

// Initialize the login form when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.loginForm = new LoginForm();
    
    // Show demo credentials hint in console
    console.log('Demo login credentials:');
    console.log('Admin: admin@fraudshield.com / admin123');
    console.log('User: user@fraudshield.com / user123');
    console.log('Demo: demo@fraudshield.com / demo123');
});