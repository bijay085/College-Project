class ModernValidator {
  constructor() {
    this.validators = new Map();
    this.debounceTimers = new Map();
    this.isSubmitting = false;
    this.validationState = new Map(); // Track validation state for each field
    this.init();
  }

  init() {
    this.setupValidators();
    this.attachEventListeners();
    this.addStyles();
  }

  showError(input, message, type = 'error') {
    this.clearError(input);
    
    const formGroup = input.closest('.form-group') || input.parentElement;
    const errorDiv = document.createElement('div');
    errorDiv.className = `input-error ${type}`;
    errorDiv.setAttribute('role', 'alert');
    errorDiv.setAttribute('aria-live', 'polite');
    
    const icon = type === 'warning' ? '⚠️' : type === 'success' ? '✅' : '❌';
    errorDiv.innerHTML = `<span class="error-icon">${icon}</span><span class="error-text">${message}</span>`;
    
    formGroup.appendChild(errorDiv);
    input.classList.add('error-border', type);
    
    // Update validation state
    if (type === 'error') {
      this.validationState.set(input.id, false);
    } else if (type === 'success') {
      this.validationState.set(input.id, true);
    }
    
    requestAnimationFrame(() => {
      errorDiv.style.opacity = '1';
      errorDiv.style.transform = 'translateY(0)';
    });

    if (type === 'error') {
      input.style.animation = 'shake 0.4s ease-in-out';
      setTimeout(() => input.style.animation = '', 400);
    }

    if (type === 'success') {
      setTimeout(() => this.clearError(input), 3000);
    }
  }

  clearError(input) {
    const formGroup = input.closest('.form-group') || input.parentElement;
    const error = formGroup.querySelector('.input-error');
    
    if (error) {
      error.style.opacity = '0';
      error.style.transform = 'translateY(-10px)';
      setTimeout(() => error.remove(), 200);
    }
    
    input.classList.remove('error-border', 'error', 'warning', 'success');
  }

  debounceValidation(input, validator, delay = 500) {
    const key = input.id || input.name;
    
    if (this.debounceTimers.has(key)) {
      clearTimeout(this.debounceTimers.get(key));
    }
    
    const timer = setTimeout(() => {
      validator(input);
      this.debounceTimers.delete(key);
    }, delay);
    
    this.debounceTimers.set(key, timer);
  }

  validateName(input) {
    this.clearError(input);
    const value = input.value.trim();
    
    if (!value) {
      this.showError(input, "Please enter your full name");
      return false;
    }
    
    if (value.length < 2) {
      this.showError(input, "Name must be at least 2 characters long");
      return false;
    }
    
    if (!/^[a-zA-Z\s'-]+$/.test(value)) {
      this.showError(input, "Name can only contain letters, spaces, hyphens, and apostrophes");
      return false;
    }
    
    if (value.split(' ').length < 2) {
      this.showError(input, "Please enter your full name (first and last)", 'warning');
      this.validationState.set(input.id, true); // Allow but warn
      return true;
    }
    
    this.showError(input, "Name looks good!", 'success');
    return true;
  }

  validateEmail(input) {
    this.clearError(input);
    const value = input.value.trim();
    
    if (!value) {
      this.showError(input, "Email address is required");
      return false;
    }
    
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    
    if (!emailRegex.test(value)) {
      this.showError(input, "Please enter a valid email address");
      return false;
    }
    
    const commonDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
    const domain = value.split('@')[1];
    const suggestion = this.suggestDomain(domain, commonDomains);
    
    if (suggestion && suggestion !== domain) {
      this.showError(input, `Did you mean ${value.replace(domain, suggestion)}?`, 'warning');
      this.validationState.set(input.id, true);
      return true;
    }
    
    this.showError(input, "Email verified!", 'success');
    return true;
  }

  validatePhone(input) {
    this.clearError(input);
    const value = input.value.replace(/\D/g, '');
    
    if (!value) {
      this.showError(input, "Phone number is required");
      return false;
    }
    
    if (value.length < 7 || value.length > 15) {
      this.showError(input, "Please enter a valid phone number (7-15 digits)");
      return false;
    }
    
    this.formatPhoneNumber(input);
    
    this.showError(input, "Phone number verified!", 'success');
    return true;
  }

  validateAddress(input, fieldName = "Address") {
    this.clearError(input);
    const value = input.value.trim();
    
    if (!value) {
      this.showError(input, `${fieldName} is required`);
      return false;
    }
    
    if (value.length < 5) {
      this.showError(input, `${fieldName} seems too short`);
      return false;
    }
    
    this.showError(input, `${fieldName} verified!`, 'success');
    return true;
  }

  validateZip(input) {
    this.clearError(input);
    const value = input.value.trim();
    
    if (!value) {
      this.showError(input, "ZIP/Postal code is required");
      return false;
    }
    
    const patterns = {
      US: /^\d{5}(-\d{4})?$/,
      CA: /^[A-Za-z]\d[A-Za-z][ -]?\d[A-Za-z]\d$/,
      UK: /^[A-Za-z]{1,2}\d[A-Za-z\d]?\s*\d[A-Za-z]{2}$/,
      IN: /^\d{6}$/,
      DEFAULT: /^[a-zA-Z0-9\s-]{3,12}$/
    };
    
    const country = document.getElementById('billingCountry')?.value || 'DEFAULT';
    const pattern = patterns[country] || patterns.DEFAULT;
    
    if (!pattern.test(value)) {
      this.showError(input, "Please enter a valid ZIP/postal code");
      return false;
    }
    
    this.showError(input, "ZIP code verified!", 'success');
    return true;
  }

  validateCardNumber(input) {
    this.clearError(input);
    const value = input.value.replace(/\s+/g, '');
    
    if (!value) {
      this.showError(input, "Card number is required");
      return false;
    }
    
    if (!/^\d{13,19}$/.test(value)) {
      this.showError(input, "Card number must be 13-19 digits");
      return false;
    }
    
    if (!this.validateLuhn(value)) {
      this.showError(input, "Invalid card number");
      return false;
    }
    
    const cardType = this.detectCardType(value);
    this.updateCardBrands(cardType);
    
    this.showError(input, `Valid ${cardType} card detected!`, 'success');
    return true;
  }

  validateExpiry(input) {
    this.clearError(input);
    const value = input.value;
    
    if (!value) {
      this.showError(input, "Expiry date is required");
      return false;
    }
    
    const match = value.match(/^(0[1-9]|1[0-2])\/([0-9]{2})$/);
    if (!match) {
      this.showError(input, "Expiry must be in MM/YY format");
      return false;
    }
    
    const month = parseInt(match[1], 10);
    const year = 2000 + parseInt(match[2], 10);
    const expiry = new Date(year, month - 1);
    const now = new Date();
    now.setDate(1);
    
    if (expiry < now) {
      this.showError(input, "Card has expired");
      return false;
    }
    
    const threeMonthsFromNow = new Date();
    threeMonthsFromNow.setMonth(threeMonthsFromNow.getMonth() + 3);
    
    if (expiry < threeMonthsFromNow) {
      this.showError(input, "Card expires soon", 'warning');
      this.validationState.set(input.id, true);
      return true;
    }
    
    this.showError(input, "Expiry date verified!", 'success');
    return true;
  }

  validateCVV(input) {
    this.clearError(input);
    const value = input.value.trim();
    
    if (!value) {
      this.showError(input, "CVV is required");
      return false;
    }
    
    if (!/^\d{3,4}$/.test(value)) {
      this.showError(input, "CVV must be 3 or 4 digits");
      return false;
    }
    
    this.showError(input, "CVV verified!", 'success');
    return true;
  }

  validateQuantity(input) {
    this.clearError(input);
    const value = parseInt(input.value, 10);
    
    if (isNaN(value) || value < 1) {
      this.showError(input, "Quantity must be at least 1");
      return false;
    }
    
    if (value > 10) {
      this.showError(input, "Maximum quantity is 10", 'warning');
      input.value = 10;
      this.validationState.set(input.id, true);
      return true;
    }
    
    this.validationState.set(input.id, true);
    return true;
  }

  validateSelect(input) {
    this.clearError(input);
    
    if (!input.value) {
      this.showError(input, "Please select a country");
      return false;
    }
    
    this.showError(input, "Country selected!", 'success');
    return true;
  }

  validateCheckbox(input, message) {
    const formGroup = input.closest('.verification-card') || input.parentElement;
    const existingError = formGroup.querySelector('.input-error');
    
    if (existingError) {
      existingError.remove();
    }
    
    if (!input.checked) {
      const errorDiv = document.createElement('div');
      errorDiv.className = 'input-error error';
      errorDiv.style.cssText = 'opacity: 1; transform: translateY(0);';
      errorDiv.innerHTML = `<span class="error-icon">❌</span><span class="error-text">${message}</span>`;
      formGroup.appendChild(errorDiv);
      formGroup.classList.add('error-border');
      this.validationState.set(input.id, false);
      return false;
    }
    
    formGroup.classList.remove('error-border');
    this.validationState.set(input.id, true);
    return true;
  }

  validateLuhn(cardNumber) {
    let sum = 0;
    let shouldDouble = false;
    
    for (let i = cardNumber.length - 1; i >= 0; i--) {
      let digit = parseInt(cardNumber.charAt(i));
      
      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      
      sum += digit;
      shouldDouble = !shouldDouble;
    }
    
    return sum % 10 === 0;
  }

  detectCardType(cardNumber) {
    const patterns = {
      visa: /^4/,
      mastercard: /^5[1-5]|^2[2-7]/,
      amex: /^3[47]/,
      discover: /^6(?:011|5)/,
      diners: /^3[0689]/,
      jcb: /^35/
    };
    
    for (const [type, pattern] of Object.entries(patterns)) {
      if (pattern.test(cardNumber)) {
        return type.charAt(0).toUpperCase() + type.slice(1);
      }
    }
    
    return 'Unknown';
  }

  updateCardBrands(detectedType) {
    const brands = document.querySelectorAll('.card-brand');
    brands.forEach(brand => {
      brand.style.opacity = '0.3';
      if (brand.classList.contains(detectedType.toLowerCase())) {
        brand.style.opacity = '1';
        brand.style.transform = 'scale(1.1)';
      }
    });
  }

  suggestDomain(domain, commonDomains) {
    const threshold = 2;
    
    for (const commonDomain of commonDomains) {
      if (this.levenshteinDistance(domain, commonDomain) <= threshold) {
        return commonDomain;
      }
    }
    
    return null;
  }

  levenshteinDistance(str1, str2) {
    const matrix = [];
    
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }
    
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }
    
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }
    
    return matrix[str2.length][str1.length];
  }

  formatPhoneNumber(input) {
    let value = input.value.replace(/\D/g, '');
    
    if (value.length >= 10) {
      value = value.replace(/(\d{3})(\d{3})(\d{4})/, '($1) $2-$3');
    } else if (value.length >= 6) {
      value = value.replace(/(\d{3})(\d{3})/, '($1) $2');
    } else if (value.length >= 3) {
      value = value.replace(/(\d{3})/, '($1)');
    }
    
    input.value = value;
  }

  setupValidators() {
    this.validators.set('name', (input) => this.validateName(input));
    this.validators.set('email', (input) => this.validateEmail(input));
    this.validators.set('phone', (input) => this.validatePhone(input));
    this.validators.set('billingAddress', (input) => this.validateAddress(input, 'Billing address'));
    this.validators.set('city', (input) => this.validateAddress(input, 'City'));
    this.validators.set('state', (input) => this.validateAddress(input, 'State/Province'));
    this.validators.set('zip', (input) => this.validateZip(input));
    this.validators.set('billingCountry', (input) => this.validateSelect(input));
    this.validators.set('cardNumber', (input) => this.validateCardNumber(input));
    this.validators.set('expiry', (input) => this.validateExpiry(input));
    this.validators.set('cvv', (input) => this.validateCVV(input));
    this.validators.set('quantity', (input) => this.validateQuantity(input));
  }

  attachEventListeners() {
    document.addEventListener('DOMContentLoaded', () => {
      const form = document.getElementById('checkoutForm');
      if (!form) return;

      // Prevent form submission with Enter key unless form is valid
      form.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && e.target.tagName !== 'BUTTON') {
          e.preventDefault();
          return false;
        }
      });

      // Form submission
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        e.stopPropagation();
        return this.handleSubmit(e);
      });

      // Live validation
      this.validators.forEach((validator, fieldId) => {
        const field = document.getElementById(fieldId);
        if (!field) return;

        // Initialize validation state
        this.validationState.set(fieldId, false);

        // Blur validation (immediate)
        field.addEventListener('blur', () => {
          if (field.value.trim() || field.hasAttribute('required')) {
            validator(field);
          }
        });

        // Input validation (debounced)
        field.addEventListener('input', () => {
          this.clearError(field);
          if (field.value.trim()) {
            this.debounceValidation(field, validator);
          } else if (field.hasAttribute('required')) {
            this.validationState.set(fieldId, false);
          }
        });
      });

      // Special formatting handlers
      const cardNumber = document.getElementById('cardNumber');
      if (cardNumber) {
        cardNumber.addEventListener('input', (e) => {
          let value = e.target.value.replace(/\D/g, '');
          value = value.replace(/(\d{4})(?=\d)/g, '$1 ');
          e.target.value = value;
        });
      }

      const expiry = document.getElementById('expiry');
      if (expiry) {
        expiry.addEventListener('input', (e) => {
          let value = e.target.value.replace(/\D/g, '');
          if (value.length >= 2) {
            value = value.substring(0, 2) + '/' + value.substring(2, 4);
          }
          e.target.value = value;
        });
      }

      // Checkbox validation - OPTIONAL, no validation needed
      const checkboxes = ['emailVerified', 'phoneVerified'];
      checkboxes.forEach(id => {
        const checkbox = document.getElementById(id);
        if (checkbox) {
          // Set to true by default since they're optional
          this.validationState.set(id, true);
          
          // Just track the state, no error messages
          checkbox.addEventListener('change', () => {
            // Always valid since it's optional
            this.validationState.set(id, true);
            this.updateSubmitButton();
          });
        }
      });

      // Add submit button state management
      this.updateSubmitButton();
    });
  }

  isFormValid() {
    const requiredFields = [
      'name', 'email', 'phone', 'billingAddress', 'city', 
      'state', 'zip', 'billingCountry', 'cardNumber', 
      'expiry', 'cvv'
      // Removed 'emailVerified' and 'phoneVerified' - they are optional
    ];

    for (const fieldId of requiredFields) {
      if (!this.validationState.get(fieldId)) {
        return false;
      }
    }

    return true;
  }

  updateSubmitButton() {
    const submitBtn = document.querySelector('.submit-btn');
    if (!submitBtn) return;

    // Check form validity on any change
    const form = document.getElementById('checkoutForm');
    if (!form) return;

    const updateBtn = () => {
      const isValid = this.isFormValid();
      if (isValid) {
        submitBtn.classList.remove('disabled');
        submitBtn.removeAttribute('disabled');
      } else {
        submitBtn.classList.add('disabled');
        submitBtn.setAttribute('disabled', 'disabled');
      }
    };

    // Listen for any input changes
    form.addEventListener('input', updateBtn);
    form.addEventListener('change', updateBtn);

    // Initial check
    updateBtn();
  }

  handleSubmit(e) {
    e.preventDefault();
    
    if (this.isSubmitting) {
      return false;
    }

    let isValid = true;
    const fields = [
      'name', 'email', 'phone', 'billingAddress', 'city', 
      'state', 'zip', 'billingCountry', 'cardNumber', 
      'expiry', 'cvv', 'quantity'
    ];

    // Clear all previous errors
    document.querySelectorAll('.input-error').forEach(error => error.remove());

    // Validate all fields
    for (const fieldId of fields) {
      const field = document.getElementById(fieldId);
      const validator = this.validators.get(fieldId);
      
      if (field && validator) {
        const fieldValid = validator(field);
        if (!fieldValid) {
          isValid = false;
        }
      }
    }

    // Don't validate checkboxes - they're optional
    // Just get their values for the fraud check
    const emailVerified = document.getElementById('emailVerified');
    const phoneVerified = document.getElementById('phoneVerified');

    if (!isValid) {
      this.focusFirstError();
      this.showValidationSummary();
      
      // Shake the submit button
      const submitBtn = document.querySelector('.submit-btn');
      if (submitBtn) {
        submitBtn.style.animation = 'shake 0.5s ease-in-out';
        setTimeout(() => submitBtn.style.animation = '', 500);
      }
      
      return false;
    }

    // If valid, allow form submission
    this.isSubmitting = true;
    const submitBtn = document.querySelector('.submit-btn');
    if (submitBtn) {
      submitBtn.classList.add('loading');
    }

    // Return true to allow fraud check to proceed
    return true;
  }

  focusFirstError() {
    const firstError = document.querySelector('.error-border');
    if (firstError) {
      firstError.scrollIntoView({ 
        behavior: 'smooth', 
        block: 'center',
        inline: 'nearest'
      });
      firstError.focus();
    }
  }

  showValidationSummary() {
    const errors = document.querySelectorAll('.input-error.error');
    if (errors.length === 0) return;

    const toast = document.createElement('div');
    toast.className = 'validation-toast error-toast';
    toast.innerHTML = `
      <div class="toast-content">
        <span class="toast-icon">⚠️</span>
        <span class="toast-text">Please fix ${errors.length} error${errors.length > 1 ? 's' : ''} before continuing</span>
      </div>
    `;

    document.body.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '1';
      toast.style.transform = 'translateY(0)';
    }, 10);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(-20px)';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  addStyles() {
    const style = document.createElement('style');
    style.textContent = `
      .input-error {
        display: flex;
        align-items: center;
        gap: 6px;
        margin-top: 6px;
        font-size: 12px;
        opacity: 0;
        transform: translateY(-10px);
        transition: all 0.2s ease-out;
      }
      
      .input-error.error {
        color: var(--error);
      }
      
      .input-error.warning {
        color: var(--warning);
      }
      
      .input-error.success {
        color: var(--success);
      }
      
      .error-border {
        border-color: var(--error) !important;
        box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.1) !important;
      }
      
      .verification-card.error-border {
        border-color: var(--error) !important;
        background: rgba(239, 68, 68, 0.05);
        box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.1) !important;
      }
      
      .verification-card .input-error {
        margin-top: 12px;
        font-weight: 500;
      }
      
      @keyframes shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-5px); }
        75% { transform: translateX(5px); }
      }
      
      .validation-toast {
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--glass-bg);
        backdrop-filter: blur(12px);
        border: 1px solid var(--error);
        border-radius: 12px;
        padding: 16px;
        z-index: 10001;
        opacity: 0;
        transform: translateY(-20px);
        transition: all 0.3s ease-out;
        max-width: 300px;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
      }
      
      .error-toast {
        background: rgba(239, 68, 68, 0.1);
        border-color: var(--error);
      }
      
      .toast-content {
        display: flex;
        align-items: center;
        gap: 8px;
        color: var(--text-primary);
        font-size: 14px;
        font-weight: 500;
      }
      
      .toast-icon {
        font-size: 16px;
      }
      
      .submit-btn.disabled {
        opacity: 0.5;
        cursor: not-allowed;
        background: var(--surface-light);
      }
      
      .submit-btn.disabled:hover {
        transform: none;
        box-shadow: var(--shadow-lg);
      }
    `;
    document.head.appendChild(style);
  }
}

// Initialize the validator
const validator = new ModernValidator();