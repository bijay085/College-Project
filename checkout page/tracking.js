class FraudShieldTracker {
  constructor() {
    this.config = {
      apiEndpoint: 'http://127.0.0.1:5000/fraud-check',
      maxRetries: 3,
      retryDelay: 1000,
      trackingEnabled: true,
      debugMode: true
    };

    this.sessionData = {
      startTime: Date.now(),
      pageLoadTime: performance.now(),
      interactions: [],
      behaviorMetrics: {
        mouseMoves: 0,
        keyPresses: 0,
        clicks: 0,
        scrollEvents: 0,
        focusEvents: 0,
        idleTime: 0,
        suspiciousActivity: []
      },
      deviceInfo: {},
      eventTimeline: {
        pageLoad: Date.now(),
        firstInteraction: null,
        firstMouseMove: null,
        firstKeyPress: null,
        firstClick: null,
        formStart: null,
        formSubmit: null
      }
    };

    this.fingerprint = null;
    this.lastActivity = Date.now();
    this.idleTimer = null;
    this.initialized = false;

    this.init();
  }

  async init() {
    try {
      await this.setupDeviceFingerprinting();
      this.collectDeviceInfo();
      this.setupBehaviorTracking();
      this.setupPerformanceMonitoring();
      this.setupFormHooks();
      this.displayStatus();
      this.initialized = true;
      
      if (this.config.debugMode) {
        console.log('🛡️ FraudShield Tracker initialized', this.sessionData);
      }
    } catch (error) {
      console.error('FraudShield initialization failed:', error);
    }
  }

  async setupDeviceFingerprinting() {
    try {
      if (typeof FingerprintJS === 'undefined') {
        console.warn('🔍 FingerprintJS not available, using fallback fingerprinting');
        this.fingerprint = this.generateFallbackFingerprint();
        return;
      }

      const fp = await FingerprintJS.load({
        monitoring: false
      });
      
      const result = await fp.get();
      this.fingerprint = result.visitorId;
      
      if (this.config.debugMode) {
        console.log('🔍 Device fingerprint generated:', this.fingerprint);
      }
    } catch (error) {
      console.warn('🔍 Fingerprinting failed, using fallback:', error);
      this.fingerprint = this.generateFallbackFingerprint();
    }
  }

  generateFallbackFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('FraudShield fingerprint', 2, 2);
    
    const components = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      new Date().getTimezoneOffset(),
      !!navigator.cookieEnabled,
      typeof localStorage !== 'undefined',
      canvas.toDataURL()
    ];
    
    return this.simpleHash(components.join('|'));
  }

  simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  collectDeviceInfo() {
    this.sessionData.deviceInfo = {
      userAgent: navigator.userAgent,
      language: navigator.language,
      languages: navigator.languages || [],
      platform: navigator.platform,
      cookieEnabled: navigator.cookieEnabled,
      onLine: navigator.onLine,
      doNotTrack: navigator.doNotTrack,
      hardwareConcurrency: navigator.hardwareConcurrency || 0,
      maxTouchPoints: navigator.maxTouchPoints || 0,
      screen: {
        width: screen.width,
        height: screen.height,
        colorDepth: screen.colorDepth,
        pixelDepth: screen.pixelDepth,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight
      },
      window: {
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight,
        outerWidth: window.outerWidth,
        outerHeight: window.outerHeight,
        devicePixelRatio: window.devicePixelRatio || 1
      },
      timezone: {
        offset: new Date().getTimezoneOffset(),
        zone: Intl.DateTimeFormat().resolvedOptions().timeZone
      },
      connection: this.getConnectionInfo(),
      performance: this.getPerformanceMetrics()
    };
  }

  getConnectionInfo() {
    const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!connection) return null;
    
    return {
      effectiveType: connection.effectiveType,
      downlink: connection.downlink,
      rtt: connection.rtt,
      saveData: connection.saveData
    };
  }

  getPerformanceMetrics() {
    if (!performance.timing) return null;
    
    const timing = performance.timing;
    return {
      navigationStart: timing.navigationStart,
      domContentLoaded: timing.domContentLoadedEventEnd - timing.navigationStart,
      loadComplete: timing.loadEventEnd - timing.navigationStart,
      dnsLookup: timing.domainLookupEnd - timing.domainLookupStart,
      tcpConnection: timing.connectEnd - timing.connectStart,
      serverResponse: timing.responseEnd - timing.requestStart
    };
  }

  setupBehaviorTracking() {
    let mouseThrottle = false;
    document.addEventListener('mousemove', (e) => {
      if (mouseThrottle) return;
      mouseThrottle = true;
      setTimeout(() => mouseThrottle = false, 50);
      
      this.trackInteraction('mousemove', {
        x: e.clientX,
        y: e.clientY,
        timestamp: Date.now()
      });
      
      this.sessionData.behaviorMetrics.mouseMoves++;
      if (!this.sessionData.eventTimeline.firstMouseMove) {
        this.sessionData.eventTimeline.firstMouseMove = Date.now();
      }
    });

    document.addEventListener('keydown', (e) => {
      this.trackInteraction('keydown', {
        key: e.key,
        code: e.code,
        ctrlKey: e.ctrlKey,
        shiftKey: e.shiftKey,
        altKey: e.altKey,
        timestamp: Date.now()
      });
      
      this.sessionData.behaviorMetrics.keyPresses++;
      if (!this.sessionData.eventTimeline.firstKeyPress) {
        this.sessionData.eventTimeline.firstKeyPress = Date.now();
      }
      
      if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I')) {
        this.flagSuspiciousActivity('dev_tools_attempt');
      }
    });

    document.addEventListener('click', (e) => {
      this.trackInteraction('click', {
        target: e.target.tagName,
        x: e.clientX,
        y: e.clientY,
        timestamp: Date.now()
      });
      
      this.sessionData.behaviorMetrics.clicks++;
      if (!this.sessionData.eventTimeline.firstClick) {
        this.sessionData.eventTimeline.firstClick = Date.now();
      }
    });

    let scrollThrottle = false;
    document.addEventListener('scroll', () => {
      if (scrollThrottle) return;
      scrollThrottle = true;
      setTimeout(() => scrollThrottle = false, 100);
      
      this.sessionData.behaviorMetrics.scrollEvents++;
      this.trackInteraction('scroll', {
        scrollY: window.scrollY,
        timestamp: Date.now()
      });
    });

    document.addEventListener('focusin', (e) => {
      this.sessionData.behaviorMetrics.focusEvents++;
      this.trackInteraction('focus', {
        target: e.target.id || e.target.tagName,
        timestamp: Date.now()
      });
    });

    document.addEventListener('visibilitychange', () => {
      this.trackInteraction('visibility_change', {
        hidden: document.hidden,
        timestamp: Date.now()
      });
      
      if (document.hidden) {
        this.startIdleTracking();
      } else {
        this.stopIdleTracking();
      }
    });

    document.addEventListener('contextmenu', (e) => {
      this.flagSuspiciousActivity('context_menu_usage');
    });

    document.addEventListener('paste', (e) => {
      this.trackInteraction('paste', {
        target: e.target.id || e.target.tagName,
        timestamp: Date.now()
      });
    });

    document.addEventListener('copy', (e) => {
      this.flagSuspiciousActivity('copy_attempt');
    });

    this.startIdleTracking();
  }

  trackInteraction(type, data) {
    this.lastActivity = Date.now();
    
    if (!this.sessionData.eventTimeline.firstInteraction) {
      this.sessionData.eventTimeline.firstInteraction = Date.now();
    }
    
    this.sessionData.interactions.push({
      type,
      data,
      timestamp: Date.now()
    });
    
    if (this.sessionData.interactions.length > 100) {
      this.sessionData.interactions = this.sessionData.interactions.slice(-100);
    }
  }

  startIdleTracking() {
    this.stopIdleTracking();
    this.idleTimer = setInterval(() => {
      const idleTime = Date.now() - this.lastActivity;
      if (idleTime > 30000) {
        this.sessionData.behaviorMetrics.idleTime += 1000;
      }
    }, 1000);
  }

  stopIdleTracking() {
    if (this.idleTimer) {
      clearInterval(this.idleTimer);
      this.idleTimer = null;
    }
  }

  flagSuspiciousActivity(type, details = {}) {
    this.sessionData.behaviorMetrics.suspiciousActivity.push({
      type,
      details,
      timestamp: Date.now()
    });
    
    if (this.config.debugMode) {
      console.warn('🚨 Suspicious activity detected:', type, details);
    }
  }

  setupPerformanceMonitoring() {
    if ('PerformanceObserver' in window) {
      try {
        const observer = new PerformanceObserver((list) => {
          const entries = list.getEntries();
          entries.forEach(entry => {
            if (entry.entryType === 'measure' && entry.duration > 1000) {
              this.flagSuspiciousActivity('performance_anomaly', {
                name: entry.name,
                duration: entry.duration
              });
            }
          });
        });
        
        observer.observe({ entryTypes: ['measure', 'navigation'] });
      } catch (error) {
        console.warn('Performance monitoring not available:', error);
      }
    }
  }

  setupFormHooks() {
    const form = document.getElementById('checkoutForm');
    if (!form) return;

    const inputs = form.querySelectorAll('input, select, textarea');
    inputs.forEach(input => {
      input.addEventListener('focus', () => {
        if (!this.sessionData.eventTimeline.formStart) {
          this.sessionData.eventTimeline.formStart = Date.now();
        }
      }, { once: true });
    });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      e.stopPropagation();
      
      this.sessionData.eventTimeline.formSubmit = Date.now();
      await this.handleFormSubmission(e);
      
      return false;
    });
  }

  async handleFormSubmission(event) {
    if (!this.initialized) {
      console.warn('🛡️ FraudShield not initialized, skipping fraud check');
      return;
    }

    try {
      const fraudData = this.collectFraudData();
      
      if (this.config.debugMode) {
        console.log('📊 Fraud data collected:', fraudData);
      }
      
      await this.sendToBackend(fraudData);
    } catch (error) {
      console.error('🛡️ Fraud check failed:', error);
      this.handleFraudCheckError(error);
    }
  }

  collectFraudData() {
    const now = Date.now();
    const checkoutTime = ((now - this.sessionData.startTime) / 1000).toFixed(2);
    
    const formData = this.getFormData();
    
    const behaviorScore = this.calculateBehaviorScore();
    
    return {
      api_key: this.getApiKey(),
      user_email: this.getUserEmail(),
      
      session_id: this.generateSessionId(),
      timestamp: new Date().toISOString(),
      checkout_time: parseFloat(checkoutTime),
      
      device_fingerprint: this.fingerprint,
      device_info: this.sessionData.deviceInfo,
      
      behavior_metrics: {
        ...this.sessionData.behaviorMetrics,
        typing_speed: this.calculateTypingSpeed(),
        mouse_velocity: this.calculateMouseVelocity(),
        interaction_patterns: this.analyzeInteractionPatterns(),
        behavior_score: behaviorScore
      },
      
      event_timeline: this.sessionData.eventTimeline,
      
      ...formData,
      
      risk_indicators: this.assessRiskIndicators(),
      
      page_performance: this.sessionData.deviceInfo.performance
    };
  }

  getFormData() {
    const data = {};
    
    try {
      data.product = this.getElementValue('product');
      data.quantity = parseInt(this.getElementValue('quantity') || '1');
      data.expected_price = parseFloat(this.getElementValue('expectedPrice') || '0');
      data.actual_price = parseFloat(this.getElementValue('actualPrice') || '0');
      data.price = data.actual_price || data.expected_price;
      
      data.full_name = this.sanitizeString(this.getElementValue('name'));
      data.email = this.sanitizeEmail(this.getElementValue('email'));
      data.phone = this.sanitizePhone(this.getElementValue('phone'));
      
      data.billing_address = this.sanitizeString(this.getElementValue('billingAddress'));
      data.billing_city = this.sanitizeString(this.getElementValue('city'));
      data.billing_state = this.sanitizeString(this.getElementValue('state'));
      data.billing_zip = this.sanitizeString(this.getElementValue('zip'));
      data.billing_country = this.getElementValue('billingCountry');
      
      data.email_verified = this.getCheckboxValue('emailVerified');
      data.phone_verified = this.getCheckboxValue('phoneVerified');
      
      const cardNumber = this.getElementValue('cardNumber');
      data.card_bin = this.extractBIN(cardNumber);
      data.card_type = this.detectCardType(cardNumber);
      data.card_token = this.tokenizeCard(cardNumber);
      data.card_number = cardNumber;
      
      data.total_amount = data.actual_price || data.expected_price * data.quantity;
      
      data.fingerprint = this.fingerprint;
      data.ip = this.sessionData.deviceInfo.ip || '127.0.0.1';
      
    } catch (error) {
      console.error('Error collecting form data:', error);
    }
    
    return data;
  }

  getElementValue(id) {
    const element = document.getElementById(id);
    return element ? element.value.trim() : null;
  }

  getCheckboxValue(id) {
    const element = document.getElementById(id);
    return element ? element.checked : false;
  }

  sanitizeString(str) {
    return str ? str.replace(/[<>\"'&]/g, '').trim() : null;
  }

  sanitizeEmail(email) {
    if (!email) return null;
    return email.toLowerCase().replace(/[<>\"'&]/g, '').trim();
  }

  sanitizePhone(phone) {
    if (!phone) return null;
    return phone.replace(/[^\d+\-\s()]/g, '').trim();
  }

  extractBIN(cardNumber) {
    if (!cardNumber) return null;
    const digits = cardNumber.replace(/\D/g, '');
    return digits.length >= 6 ? digits.substring(0, 6) : null;
  }

  detectCardType(cardNumber) {
    if (!cardNumber) return 'unknown';
    const digits = cardNumber.replace(/\D/g, '');
    
    if (digits.startsWith('4')) return 'visa';
    if (digits.startsWith('5') || digits.startsWith('2')) return 'mastercard';
    if (digits.startsWith('3')) return 'amex';
    return 'unknown';
  }

  tokenizeCard(cardNumber) {
    if (!cardNumber) return null;
    const digits = cardNumber.replace(/\D/g, '');
    return 'tok_' + this.simpleHash(digits + Date.now());
  }

  calculateBehaviorScore() {
    const metrics = this.sessionData.behaviorMetrics;
    const timeline = this.sessionData.eventTimeline;
    
    let score = 100;
    
    score -= metrics.suspiciousActivity.length * 10;
    
    const totalTime = Date.now() - this.sessionData.startTime;
    const interactionRate = this.sessionData.interactions.length / (totalTime / 1000);
    
    if (interactionRate > 10) score -= 20;
    if (interactionRate < 0.1) score -= 15;
    
    if (timeline.formSubmit && timeline.formStart) {
      const fillTime = timeline.formSubmit - timeline.formStart;
      if (fillTime < 10000) score -= 30;
      if (fillTime > 600000) score -= 10;
    }
    
    return Math.max(0, Math.min(100, score));
  }

  calculateTypingSpeed() {
    const keyPresses = this.sessionData.behaviorMetrics.keyPresses;
    const totalTime = (Date.now() - this.sessionData.startTime) / 1000;
    return totalTime > 0 ? (keyPresses / totalTime * 60).toFixed(2) : 0;
  }

  calculateMouseVelocity() {
    const mouseMoves = this.sessionData.interactions.filter(i => i.type === 'mousemove');
    if (mouseMoves.length < 2) return 0;
    
    let totalDistance = 0;
    for (let i = 1; i < mouseMoves.length; i++) {
      const prev = mouseMoves[i - 1].data;
      const curr = mouseMoves[i].data;
      const distance = Math.sqrt(Math.pow(curr.x - prev.x, 2) + Math.pow(curr.y - prev.y, 2));
      totalDistance += distance;
    }
    
    const totalTime = (mouseMoves[mouseMoves.length - 1].timestamp - mouseMoves[0].timestamp) / 1000;
    return totalTime > 0 ? (totalDistance / totalTime).toFixed(2) : 0;
  }

  analyzeInteractionPatterns() {
    const interactions = this.sessionData.interactions;
    const patterns = {
      regularityScore: 0,
      diversityScore: 0,
      humanLikeScore: 0
    };
    
    if (interactions.length < 5) return patterns;
    
    const intervals = [];
    for (let i = 1; i < interactions.length; i++) {
      intervals.push(interactions[i].timestamp - interactions[i - 1].timestamp);
    }
    
    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((a, b) => a + Math.pow(b - avgInterval, 2), 0) / intervals.length;
    patterns.regularityScore = Math.min(100, variance / 1000);
    
    const types = new Set(interactions.map(i => i.type));
    patterns.diversityScore = Math.min(100, types.size * 20);
    
    patterns.humanLikeScore = (patterns.regularityScore + patterns.diversityScore) / 2;
    
    return patterns;
  }

  assessRiskIndicators() {
    const indicators = [];
    
    if (this.sessionData.behaviorMetrics.suspiciousActivity.length > 0) {
      indicators.push('suspicious_activity_detected');
    }
    
    if (this.sessionData.deviceInfo.screen.width < 800 || this.sessionData.deviceInfo.screen.height < 600) {
      indicators.push('unusual_screen_size');
    }
    
    if (!this.sessionData.deviceInfo.cookieEnabled) {
      indicators.push('cookies_disabled');
    }
    
    if (this.sessionData.deviceInfo.doNotTrack === '1') {
      indicators.push('do_not_track_enabled');
    }
    
    const behaviorScore = this.calculateBehaviorScore();
    if (behaviorScore < 50) {
      indicators.push('low_behavior_score');
    }
    
    return indicators;
  }

  generateSessionId() {
    return 'sess_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  getApiKey() {
    const userData = sessionStorage.getItem('fraudshield_user');
    const apiKey = sessionStorage.getItem('fraudshield_api_key');
    if (userData && apiKey) return apiKey;
    return 'fsk_y5JeZJTeAAxAFpv72FcQWv_IrZZdaCfeIipy3JTMtxo';
  }

  getUserEmail() {
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

  async sendToBackend(payload) {
    const submitBtn = document.querySelector('.submit-btn');
    const loadingOverlay = document.getElementById('loadingOverlay');
    
    if (submitBtn) submitBtn.classList.add('loading');
    if (loadingOverlay) loadingOverlay.classList.add('active');
    
    try {
      const response = await this.makeRequest(payload);
      const result = await response.json();
      
      if (response.ok) {
        this.displayResult(result);
        this.clearStoredData();
        
        setTimeout(() => {
          if (submitBtn) submitBtn.classList.remove('loading');
          if (loadingOverlay) loadingOverlay.classList.remove('active');
        }, 500);
      } else {
        throw new Error(result.error || `API request failed with status ${response.status}`);
      }
      
    } catch (error) {
      console.error('🛡️ FraudShield API error:', error);
      this.handleFraudCheckError(error, payload);
      
      if (submitBtn) submitBtn.classList.remove('loading');
      if (loadingOverlay) loadingOverlay.classList.remove('active');
    }
  }

  async makeRequest(payload, retryCount = 0) {
    try {
      const response = await fetch(this.config.apiEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Authorization': `Bearer ${payload.api_key}`
        },
        body: JSON.stringify(payload),
        mode: 'cors',
        credentials: 'omit'
      });
      
      return response;
    } catch (error) {
      if (retryCount < this.config.maxRetries) {
        await this.delay(this.config.retryDelay * (retryCount + 1));
        return this.makeRequest(payload, retryCount + 1);
      }
      throw error;
    }
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  handleFraudCheckError(error, payload) {
    let errorMessage = '🛡️ Fraud detection temporarily unavailable.';
    
    if (error.message.includes('Invalid API key') || error.message.includes('401')) {
      errorMessage = '🔐 Authentication failed. Please check your API key.';
    } else if (error.message.includes('Network') || error.message.includes('fetch')) {
      errorMessage = '🌐 Network error. Please check your connection and ensure the API server is running.';
    } else if (error.message.includes('timeout')) {
      errorMessage = '⏱️ Request timeout. Please try again.';
    }
    
    this.showNotification(errorMessage, 'error');
    
    if (payload) {
      localStorage.setItem('fraudshield_retry_data', JSON.stringify({
        payload,
        timestamp: Date.now(),
        attempts: 1
      }));
    }
  }

  displayResult(data) {
    let resultBox = document.getElementById('fraudResult');
    if (!resultBox) {
      resultBox = document.createElement('div');
      resultBox.id = 'fraudResult';
      resultBox.className = 'fraud-result';
      const container = document.querySelector('.checkout-container');
      if (container) container.appendChild(resultBox);
    }
    
    const fraudData = data.data || data;
    const isLegit = fraudData.is_fraud !== true;
    const status = fraudData.is_fraud === true ? '❌ FRAUD DETECTED'
                 : fraudData.is_fraud === 'chance' ? '🟡 SUSPICIOUS TRANSACTION'  
                 : '✅ TRANSACTION APPROVED';
    
    const statusColor = isLegit ? 'var(--success)' : 'var(--error)';
    
    resultBox.innerHTML = `
      <div style="text-align: center; margin-bottom: 1.5rem;">
        <h3 style="color: ${statusColor}; font-size: 1.5rem; margin-bottom: 0.5rem;">
          🛡️ FraudShield Analysis Complete
        </h3>
        <div style="font-size: 1.25rem; font-weight: bold; color: ${statusColor};">
          ${status}
        </div>
      </div>
      
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
        <div style="background: var(--surface); padding: 1rem; border-radius: 0.5rem; text-align: center;">
          <div style="font-size: 2rem; font-weight: bold; color: ${statusColor};">
            ${fraudData.fraud_score || 0}
          </div>
          <div style="color: var(--text-secondary); font-size: 0.875rem;">Fraud Score</div>
        </div>
        
        <div style="background: var(--surface); padding: 1rem; border-radius: 0.5rem; text-align: center;">
          <div style="font-size: 1.25rem; font-weight: bold; color: var(--text-primary);">
            ${fraudData.decision || 'PENDING'}
          </div>
          <div style="color: var(--text-secondary); font-size: 0.875rem;">Decision</div>
        </div>
      </div>
      
      ${fraudData.reasons && fraudData.reasons.length > 0 ? `
        <div style="margin-bottom: 1.5rem;">
          <h4 style="color: var(--text-primary); margin-bottom: 0.75rem;">Analysis Details:</h4>
          <ul style="list-style: none; padding: 0; margin: 0;">
            ${fraudData.reasons.map(reason => `
              <li style="background: var(--surface); padding: 0.75rem; margin-bottom: 0.5rem; border-radius: 0.375rem; border-left: 3px solid ${statusColor};">
                ${reason}
              </li>
            `).join('')}
          </ul>
        </div>
      ` : ''}
      
      <div style="text-align: center; color: var(--text-secondary); font-size: 0.875rem;">
        Analysis completed at ${new Date(fraudData.analysis_timestamp || Date.now()).toLocaleString()}
      </div>
    `;
    
    resultBox.style.opacity = '0';
    resultBox.style.transform = 'translateY(20px)';
    resultBox.classList.add('show');
    
    requestAnimationFrame(() => {
      resultBox.style.transition = 'all 0.4s ease';
      resultBox.style.opacity = '1';
      resultBox.style.transform = 'translateY(0)';
    });
    
    setTimeout(() => {
      resultBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 200);
  }

  showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: ${type === 'error' ? 'var(--error)' : 'var(--primary)'};
      color: white;
      padding: 1rem 1.5rem;
      border-radius: 0.5rem;
      box-shadow: var(--shadow-lg);
      z-index: 10000;
      max-width: 400px;
      transform: translateX(100%);
      transition: transform 0.3s ease;
    `;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
      notification.style.transform = 'translateX(0)';
    }, 100);
    
    setTimeout(() => {
      notification.style.transform = 'translateX(100%)';
      setTimeout(() => notification.remove(), 300);
    }, 5000);
  }

  clearStoredData() {
    localStorage.removeItem('fraudshield_retry_data');
  }

  displayStatus() {
    const apiKey = this.getApiKey();
    const userEmail = this.getUserEmail();
    
    let statusDiv = document.getElementById('apiKeyStatus');
    if (!statusDiv) {
      statusDiv = document.createElement('div');
      statusDiv.id = 'apiKeyStatus';
      statusDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: rgba(30, 41, 59, 0.95);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(148, 163, 184, 0.3);
        border-radius: 0.75rem;
        padding: 1rem;
        font-size: 0.8rem;
        color: #cbd5e1;
        z-index: 9999;
        max-width: 300px;
        min-width: 200px;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.4);
        font-family: 'Inter', sans-serif;
      `;
      document.body.appendChild(statusDiv);
    }
    
    const status = userEmail && apiKey !== 'fsk_y5JeZJTeAAxAFpv72FcQWv_IrZZdaCfeIipy3JTMtxo' 
      ? { type: 'authenticated', icon: '🔐', color: 'var(--success)' }
      : apiKey 
      ? { type: 'demo', icon: '🔑', color: 'var(--warning)' }
      : { type: 'none', icon: '❌', color: 'var(--error)' };
    
    statusDiv.innerHTML = `
      <div style="color: ${status.color}; font-weight: 600; margin-bottom: 0.5rem;">
        ${status.icon} ${status.type === 'authenticated' ? 'Authenticated' : status.type === 'demo' ? 'Demo Mode' : 'Not Authenticated'}
      </div>
      ${userEmail ? `<div>User: ${userEmail}</div>` : ''}
      <div style="font-family: monospace; word-break: break-all;">
        Key: ${apiKey ? apiKey.substring(0, 15) + '...' : 'None'}
      </div>
      <div style="margin-top: 0.5rem; font-size: 0.625rem; opacity: 0.7;">
        Session: ${this.fingerprint ? this.fingerprint.substring(0, 8) : 'Unknown'}
      </div>
    `;
  }

  getSessionData() {
    return { ...this.sessionData };
  }

  exportData() {
    return {
      sessionData: this.sessionData,
      fingerprint: this.fingerprint,
      config: this.config
    };
  }
}

let fraudTracker;

document.addEventListener('DOMContentLoaded', () => {
  fraudTracker = new FraudShieldTracker();
  
  if (typeof window !== 'undefined') {
    window.fraudTracker = fraudTracker;
  }
  
  window.addEventListener('beforeunload', () => {
    if (fraudTracker) {
      fraudTracker.stopIdleTracking();
    }
  });
});

if (typeof module !== 'undefined' && module.exports) {
  module.exports = FraudShieldTracker;
}