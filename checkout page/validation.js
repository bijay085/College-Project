// Validation for checkout form

function showError(input, message) {
  let error = input.parentElement.querySelector('.input-error');
  if (!error) {
    error = document.createElement('div');
    error.className = 'input-error';
    error.style.color = '#e53e3e';
    error.style.fontSize = '13px';
    error.style.marginTop = '4px';
    input.parentElement.appendChild(error);
  }
  error.textContent = message;
  input.classList.add('error-border');
}

function clearError(input) {
  let error = input.parentElement.querySelector('.input-error');
  if (error) error.remove();
  input.classList.remove('error-border');
}

function validateName(input) {
  clearError(input);
  if (!input.value.trim() || input.value.trim().length < 2) {
    showError(input, "Please enter your full name.");
    return false;
  }
  return true;
}

function validateEmail(input) {
  clearError(input);
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!re.test(input.value.trim())) {
    showError(input, "Enter a valid email address.");
    return false;
  }
  return true;
}

function validatePhone(input) {
  clearError(input);
  const re = /^[0-9]{7,15}$/;
  if (!re.test(input.value.replace(/\D/g, ""))) {
    showError(input, "Enter a valid phone number.");
    return false;
  }
  return true;
}

function validateNotEmpty(input, msg) {
  clearError(input);
  if (!input.value.trim()) {
    showError(input, msg || "This field is required.");
    return false;
  }
  return true;
}

function validateZip(input) {
  clearError(input);
  if (!/^[a-zA-Z0-9\- ]{3,12}$/.test(input.value.trim())) {
    showError(input, "Enter a valid ZIP/postal code.");
    return false;
  }
  return true;
}

function validateCardNumber(input) {
  clearError(input);
  const value = input.value.replace(/\s+/g, '');
  if (!/^\d{13,19}$/.test(value)) {
    showError(input, "Enter a valid card number.");
    return false;
  }
  // Luhn check
  let sum = 0, shouldDouble = false;
  for (let i = value.length - 1; i >= 0; i--) {
    let digit = parseInt(value.charAt(i));
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  if (sum % 10 !== 0) {
    showError(input, "Invalid card number.");
    return false;
  }
  return true;
}

function validateExpiry(input) {
  clearError(input);
  const re = /^(0[1-9]|1[0-2])\/?([0-9]{2})$/;
  const match = input.value.match(re);
  if (!match) {
    showError(input, "Expiry must be MM/YY.");
    return false;
  }
  // Check not expired
  const now = new Date();
  const month = parseInt(match[1], 10);
  const year = 2000 + parseInt(match[2], 10);
  const expiry = new Date(year, month);
  if (expiry <= now) {
    showError(input, "Card expired.");
    return false;
  }
  return true;
}

function validateCVV(input) {
  clearError(input);
  if (!/^\d{3,4}$/.test(input.value.trim())) {
    showError(input, "CVV must be 3 or 4 digits.");
    return false;
  }
  return true;
}

function validateQuantity(input) {
  clearError(input);
  const val = parseInt(input.value, 10);
  if (isNaN(val) || val < 1) {
    showError(input, "Quantity must be at least 1.");
    return false;
  }
  return true;
}

// Attach validation on submit
document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('checkoutForm');
  if (!form) return;

  // Add error-border style
  const style = document.createElement('style');
  style.textContent = `.error-border { border-color: #e53e3e !important; box-shadow: 0 0 0 2px #fed7d7 !important; }`;
  document.head.appendChild(style);

  form.addEventListener('submit', function (e) {
    let valid = true;

    const name = document.getElementById('name');
    const email = document.getElementById('email');
    const phone = document.getElementById('phone');
    const billingAddress = document.getElementById('billingAddress');
    const city = document.getElementById('city');
    const state = document.getElementById('state');
    const zip = document.getElementById('zip');
    const billingCountry = document.getElementById('billingCountry');
    const cardNumber = document.getElementById('cardNumber');
    const expiry = document.getElementById('expiry');
    const cvv = document.getElementById('cvv');
    const quantity = document.getElementById('quantity');

    if (!validateName(name)) valid = false;
    if (!validateEmail(email)) valid = false;
    if (!validatePhone(phone)) valid = false;
    if (!validateNotEmpty(billingAddress, "Enter your address.")) valid = false;
    if (!validateNotEmpty(city, "Enter your city.")) valid = false;
    if (!validateNotEmpty(state, "Enter your state/province.")) valid = false;
    if (!validateZip(zip)) valid = false;
    if (!validateNotEmpty(billingCountry, "Select your country.")) valid = false;
    if (!validateCardNumber(cardNumber)) valid = false;
    if (!validateExpiry(expiry)) valid = false;
    if (!validateCVV(cvv)) valid = false;
    if (!validateQuantity(quantity)) valid = false;

    if (!valid) {
      e.preventDefault();
      // Do NOT clear any input fields, just prevent submission and show errors
      const firstError = form.querySelector('.error-border');
      if (firstError) firstError.scrollIntoView({ behavior: 'smooth', block: 'center' });
      return false;
    }
  });

  // Optional: live validation on blur
  [
    ['name', validateName],
    ['email', validateEmail],
    ['phone', validatePhone],
    ['billingAddress', (i) => validateNotEmpty(i, "Enter your address.")],
    ['city', (i) => validateNotEmpty(i, "Enter your city.")],
    ['state', (i) => validateNotEmpty(i, "Enter your state/province.")],
    ['zip', validateZip],
    ['billingCountry', (i) => validateNotEmpty(i, "Select your country.")],
    ['cardNumber', validateCardNumber],
    ['expiry', validateExpiry],
    ['cvv', validateCVV],
    ['quantity', validateQuantity]
  ].forEach(([id, fn]) => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('blur', () => fn(el));
      el.addEventListener('input', () => clearError(el));
    }
  });
});