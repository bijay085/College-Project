(function () {
  const startTime = Date.now();
  let mouseMoves = 0;
  let keyPresses = 0;
  let deviceFingerprint = null;
  const eventTimeline = {
    pageLoad: startTime,
    firstMouseMove: null,
    firstKeyPress: null,
    formSubmit: null
  };

  // ========== 1. Behavior Tracking ==========
  window.addEventListener("mousemove", () => {
    mouseMoves++;
    if (!eventTimeline.firstMouseMove) eventTimeline.firstMouseMove = Date.now();
  });

  window.addEventListener("keydown", () => {
    keyPresses++;
    if (!eventTimeline.firstKeyPress) eventTimeline.firstKeyPress = Date.now();
  });

  // ========== 2. Device Fingerprinting ==========
  const loadFingerprint = async () => {
    try {
      if (typeof FingerprintJS === "undefined") {
        console.warn("FingerprintJS not loaded.");
        return;
      }
      const fp = await FingerprintJS.load();
      const result = await fp.get();
      deviceFingerprint = result.visitorId;
      console.log("Device Fingerprint:", deviceFingerprint);
    } catch (err) {
      console.warn("FingerprintJS failed:", err);
    }
  };
  loadFingerprint();

  // ========== 3. Helpers ==========
  function get(id) {
    const el = document.getElementById(id);
    return el ? el.value.trim() : null;
  }

  function getNumber(id) {
    const val = get(id);
    return val ? parseFloat(val.replace(/,/g, "")) : null;
  }

  function extractBIN(cardNumber) {
    const digits = cardNumber.replace(/\D/g, "");
    return digits.length >= 6 ? digits.substring(0, 6) : null;
  }

  // ========== 4. API Key Management ==========
  function getApiKey() {
    // Check if user is authenticated and has API key
    const userData = sessionStorage.getItem('fraudshield_user');
    const apiKey = sessionStorage.getItem('fraudshield_api_key');
    
    if (userData && apiKey) {
      return apiKey;
    }
    
    // For demo purposes, you can also allow a hardcoded API key
    // Remove this in production
    return "fsk_demo_checkout_key_2024";
  }

  function getUserEmail() {
    const userData = sessionStorage.getItem('fraudshield_user');
    if (userData) {
      try {
        const parsed = JSON.parse(userData);
        return parsed.user?.email || null;
      } catch (e) {
        return null;
      }
    }
    return null;
  }

  // ========== 5. Collect Data ==========
  function collectFraudData() {
    const now = Date.now();
    eventTimeline.formSubmit = now;

    const checkoutTime = ((now - startTime) / 1000).toFixed(2);
    const cardNumber = get("cardNumber");
    const cardBIN = extractBIN(cardNumber);
    const unitPrice = getNumber("expectedPrice");
    const quantity = parseInt(get("quantity") || "1");
    const userEmail = getUserEmail();

    return {
      // Authentication
      api_key: getApiKey(),
      user_email: userEmail,
      
      // Transaction data
      timestamp: new Date().toISOString(),
      checkout_time: checkoutTime,
      typing_speed: (keyPresses / checkoutTime).toFixed(2),
      mouse_rate: (mouseMoves / checkoutTime).toFixed(2),
      user_agent: navigator.userAgent,
      language: navigator.language,
      platform: navigator.platform,
      screen_resolution: `${screen.width}x${screen.height}`,
      do_not_track: navigator.doNotTrack,
      device_fingerprint: deviceFingerprint,
      mouse_movements: mouseMoves,
      key_presses: keyPresses,
      event_timeline: eventTimeline,

      // Product
      product: get("product"),
      quantity: quantity,
      expected_price: unitPrice * quantity,
      actual_price: getNumber("actualPrice"),

      // Billing
      full_name: get("name"),
      email: get("email"),
      phone: get("phone"),
      billing_address: get("billingAddress"),
      billing_city: get("city"),
      billing_state: get("state"),
      billing_zip: get("zip"),
      billing_country: get("billingCountry"),

      // Payment - ⚠️ Use token in production!
      card_bin: cardBIN,
      card_token: "simulate_or_use_token_here",
      
      // Additional tracking
      ip: "auto_detect", // Server will detect real IP
      price: unitPrice * quantity
    };
  }

  // ========== 6. Send to Backend ==========
  async function sendToBackend(payload) {
    const button = document.querySelector(".submit-btn");
    if (button) button.disabled = true;

    try {
      const response = await fetch("http://localhost:5000/fraud-check", {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Authorization": `Bearer ${payload.api_key}` // Send API key in header too
        },
        body: JSON.stringify(payload),
      });

      const result = await response.json();
      
      if (response.ok) {
        displayResult(result);
        localStorage.removeItem("unsent_fraud_data");
      } else {
        throw new Error(result.error || "API request failed");
      }

    } catch (error) {
      console.error("FraudShield error:", error);
      
      let errorMessage = "⚠️ Error contacting fraud detection system.";
      if (error.message.includes("Invalid API key")) {
        errorMessage = "🔐 Authentication failed. Please check your API key.";
      } else if (error.message.includes("API key not found")) {
        errorMessage = "🔑 API key not found. Please contact support.";
      }
      
      alert(errorMessage);
      localStorage.setItem("unsent_fraud_data", JSON.stringify(payload));
    }

    if (button) button.disabled = false;
  }

  // ========== 7. Display Result ==========
  function displayResult(data) {
    let resultBox = document.getElementById("fraudResult");
    if (!resultBox) {
      resultBox = document.createElement("div");
      resultBox.id = "fraudResult";
      const container = document.querySelector(".checkout-container");
      if (container) container.appendChild(resultBox);
    }

    // Handle both direct response and wrapped response formats
    const fraudData = data.data || data;
    
    const status = fraudData.is_fraud === true ? "❌ FRAUD" : 
                  fraudData.is_fraud === "chance" ? "🟡 Suspicious" : "✅ Legit";

    resultBox.innerHTML = `
      <h3>🛡️ FraudShield Result</h3>
      <p><strong>Status:</strong> ${status}</p>
      <p><strong>Fraud Score:</strong> ${fraudData.fraud_score || 0}</p>
      <p><strong>Decision:</strong> ${fraudData.decision || 'unknown'}</p>
      <p><strong>Triggered Rules:</strong></p>
      <ul>${(fraudData.reasons || []).map(r => `<li>${r}</li>`).join("")}</ul>
      <p><strong>Analysis Time:</strong> ${fraudData.analysis_timestamp || 'N/A'}</p>
    `;
  }

  // ========== 8. Submit Hook ==========
  const form = document.getElementById("checkoutForm");
  if (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      
      const apiKey = getApiKey();
      if (!apiKey) {
        alert("🔑 No API key found. Please authenticate first.");
        return;
      }
      
      const data = collectFraudData();
      console.log("📦 Collected Fraud Data with API Key:", {
        ...data,
        api_key: data.api_key.substring(0, 10) + "..." // Log partial key for security
      });
      console.table(data);
      sendToBackend(data);
    });
  }

  // ========== 9. API Key Status Display ==========
  function displayApiKeyStatus() {
    const apiKey = getApiKey();
    const userEmail = getUserEmail();
    
    // Create status display
    let statusDiv = document.getElementById("apiKeyStatus");
    if (!statusDiv) {
      statusDiv = document.createElement("div");
      statusDiv.id = "apiKeyStatus";
      statusDiv.style.cssText = `
        position: fixed;
        top: 10px;
        right: 10px;
        background: #f1f5f9;
        border: 1px solid #cbd5e1;
        border-radius: 8px;
        padding: 12px;
        font-size: 12px;
        z-index: 1000;
        max-width: 300px;
      `;
      document.body.appendChild(statusDiv);
    }
    
    if (userEmail && apiKey) {
      statusDiv.innerHTML = `
        <div style="color: #059669; font-weight: 600;">🔐 Authenticated</div>
        <div style="color: #6b7280; margin-top: 4px;">User: ${userEmail}</div>
        <div style="color: #6b7280; font-family: monospace;">Key: ${apiKey.substring(0, 15)}...</div>
      `;
    } else if (apiKey) {
      statusDiv.innerHTML = `
        <div style="color: #d97706; font-weight: 600;">🔑 Demo Mode</div>
        <div style="color: #6b7280; margin-top: 4px;">Using demo API key</div>
        <div style="color: #6b7280; font-family: monospace;">Key: ${apiKey.substring(0, 15)}...</div>
      `;
    } else {
      statusDiv.innerHTML = `
        <div style="color: #dc2626; font-weight: 600;">❌ No Authentication</div>
        <div style="color: #6b7280; margin-top: 4px;">Please sign in or use demo mode</div>
      `;
    }
  }
  
  // Show API key status on page load
  displayApiKeyStatus();
  
  // Update status when session changes
  window.addEventListener('storage', displayApiKeyStatus);
  
})();