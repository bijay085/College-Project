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

  // ========== 4. Collect Data ==========
  function collectFraudData() {
    const now = Date.now();
    eventTimeline.formSubmit = now;

    const checkoutTime = ((now - startTime) / 1000).toFixed(2);
    const cardNumber = get("cardNumber");
    const cardBIN = extractBIN(cardNumber);
    const unitPrice = getNumber("expectedPrice");
    const quantity = parseInt(get("quantity") || "1");

    return {
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
      card_token: "simulate_or_use_token_here"
    };
  }

  // ========== 5. Send to Backend ==========
  async function sendToBackend(payload) {
    const button = document.querySelector(".submit-btn");
    if (button) button.disabled = true;

    try {
      const response = await fetch("http://localhost:5000/fraud-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const result = await response.json();
      displayResult(result);

      localStorage.removeItem("unsent_fraud_data");
    } catch (error) {
      console.error("FraudShield error:", error);
      alert("⚠️ Error contacting fraud detection system.");
      localStorage.setItem("unsent_fraud_data", JSON.stringify(payload));
    }

    if (button) button.disabled = false;
  }

  // ========== 6. Display Result ==========
  function displayResult(data) {
    let resultBox = document.getElementById("fraudResult");
    if (!resultBox) {
      resultBox = document.createElement("div");
      resultBox.id = "fraudResult";
      const container = document.querySelector(".checkout-container");
      if (container) container.appendChild(resultBox);
    }

    resultBox.innerHTML = `
      <h3>🛡️ FraudShield Result</h3>
      <p><strong>Status:</strong> ${data.is_fraud === true ? "❌ FRAUD" : data.is_fraud === "chance" ? "🟡 Suspicious" : "✅ Legit"}</p>
      <p><strong>Fraud Score:</strong> ${data.fraud_score}</p>
      <p><strong>Reasons:</strong></p>
      <ul>${(data.reasons || []).map(r => `<li>${r}</li>`).join("")}</ul>
    `;
  }

  // ========== 7. Submit Hook ==========
  const form = document.getElementById("checkoutForm");
  if (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      const data = collectFraudData();
      console.log("📦 Collected Fraud Data:", data);
      console.table(data);
      sendToBackend(data);
    });
  }
})();
