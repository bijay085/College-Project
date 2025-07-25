/**
 * Advanced Fraud Detection & User Behavior Tracking
 * Features: Enhanced behavioral analysis, improved performance, better error handling
 */

class FraudShieldTracker {
  constructor() {
    this.config = {
      apiEndpoint: 'http://127.0.0.1:5000/fraud-check',
      maxRetries: 3,
      retryDelay: 1000,
      trackingEnabled: true,
      debugMode: false
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
      hash = hash & hash; // Convert to 32-bit integer
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
    // Mouse movement tracking with throttling
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

    // Keyboard tracking
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
      
      // Detect suspicious key combinations
      if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I')) {
        this.flagSuspiciousActivity('dev_tools_attempt');
      }
    });

    // Click tracking
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

    // Scroll tracking
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

    // Focus tracking
    document.addEventListener('focusin', (e) => {
      this.sessionData.behaviorMetrics.focusEvents++;
      this.trackInteraction('focus', {
        target: e.target.id || e.target.tagName,
        timestamp: Date.now()
      });
    });

    // Tab visibility changes
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

    // Context menu (right-click) detection
    document.addEventListener('contextmenu', (e) => {
      this.flagSuspiciousActivity('context_menu_usage');
    });

    // Paste events (could indicate automated filling)
    document.addEventListener('paste', (e) => {
      this.trackInteraction('paste', {
        target: e.target.id || e.target.tagName,
        timestamp: Date.now()
      });
    });

    // Copy events
    document.addEventListener('copy', (e) => {
      this.flagSuspiciousActivity('copy_attempt');
    });

    // Start idle tracking
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
    
    // Keep only last 100 interactions to manage memory
    if (this.sessionData.interactions.length > 100) {
      this.sessionData.interactions = this.sessionData.interactions.slice(-100);
    }
  }

  startIdleTracking() {
    this.stopIdleTracking();
    this.idleTimer = setInterval(() => {
      const idleTime = Date.now() - this.lastActivity;
      if (idleTime > 30000) { // 30 seconds idle
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
    // Monitor performance drops that might indicate automation
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

    // Track form start
    const inputs = form.querySelectorAll('input, select, textarea');
    inputs.forEach(input => {
      input.addEventListener('focus', () => {
        if (!this.sessionData.eventTimeline.formStart) {
          this.sessionData.eventTimeline.formStart = Date.now();
        }
      }, { once: true });
    });

    // Track form submission
    form.addEventListener('submit', async (e) => {
      e.preventDefault(); // IMPORTANT: Prevent default form submission
      e.stopPropagation(); // Stop event bubbling
      
      this.sessionData.eventTimeline.formSubmit = Date.now();
      await this.handleFormSubmission(e);
      
      return false; // Extra safety to prevent form submission
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
    
    // Get form data safely
    const formData = this.getFormData();
    
    // Calculate behavior scores
    const behaviorScore = this.calculateBehaviorScore();
    
    return {
      // Authentication
      api_key: this.getApiKey(),
      user_email: this.getUserEmail(),
      
      // Session data
      session_id: this.generateSessionId(),
      timestamp: new Date().toISOString(),
      checkout_time: parseFloat(checkoutTime),
      
      // Device information
      device_fingerprint: this.fingerprint,
      device_info: this.sessionData.deviceInfo,
      
      // Behavioral metrics
      behavior_metrics: {
        ...this.sessionData.behaviorMetrics,
        typing_speed: this.calculateTypingSpeed(),
        mouse_velocity: this.calculateMouseVelocity(),
        interaction_patterns: this.analyzeInteractionPatterns(),
        behavior_score: behaviorScore
      },
      
      // Event timeline
      event_timeline: this.sessionData.eventTimeline,
      
      // Form data (sanitized)
      ...formData,
      
      // Risk indicators
      risk_indicators: this.assessRiskIndicators(),
      
      // Performance metrics
      page_performance: this.sessionData.deviceInfo.performance
    };
  }

  getFormData() {
    const data = {};
    
    try {
      // Product information
      data.product = this.getElementValue('product');
      data.quantity = parseInt(this.getElementValue('quantity') || '1');
      data.expected_price = parseFloat(this.getElementValue('expectedPrice') || '0');
      data.actual_price = parseFloat(this.getElementValue('actualPrice') || '0');
      
      // Personal information (sanitized)
      data.full_name = this.sanitizeString(this.getElementValue('name'));
      data.email = this.sanitizeEmail(this.getElementValue('email'));
      data.phone = this.sanitizePhone(this.getElementValue('phone'));
      
      // Address information
      data.billing_address = this.sanitizeString(this.getElementValue('billingAddress'));
      data.billing_city = this.sanitizeString(this.getElementValue('city'));
      data.billing_state = this.sanitizeString(this.getElementValue('state'));
      data.billing_zip = this.sanitizeString(this.getElementValue('zip'));
      data.billing_country = this.getElementValue('billingCountry');
      
      // Verification status
      data.email_verified = this.getCheckboxValue('emailVerified');
      data.phone_verified = this.getCheckboxValue('phoneVerified');
      
      // Payment information (tokenized)
      const cardNumber = this.getElementValue('cardNumber');
      data.card_bin = this.extractBIN(cardNumber);
      data.card_type = this.detectCardType(cardNumber);
      data.card_token = this.tokenizeCard(cardNumber); // In production, use real tokenization
      
      // Calculate total
      data.total_amount = data.actual_price || data.expected_price * data.quantity;
      
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
    // In production, this should use real tokenization
    if (!cardNumber) return null;
    const digits = cardNumber.replace(/\D/g, '');
    return 'tok_' + this.simpleHash(digits + Date.now());
  }

  calculateBehaviorScore() {
    const metrics = this.sessionData.behaviorMetrics;
    const timeline = this.sessionData.eventTimeline;
    
    let score = 100; // Start with perfect score
    
    // Penalize for suspicious activities
    score -= metrics.suspiciousActivity.length * 10;
    
    // Check interaction patterns
    const totalTime = Date.now() - this.sessionData.startTime;
    const interactionRate = this.sessionData.interactions.length / (totalTime / 1000);
    
    if (interactionRate > 10) score -= 20; // Too many interactions
    if (interactionRate < 0.1) score -= 15; // Too few interactions
    
    // Check timing patterns
    if (timeline.formSubmit && timeline.formStart) {
      const fillTime = timeline.formSubmit - timeline.formStart;
      if (fillTime < 10000) score -= 30; // Too fast (less than 10 seconds)
      if (fillTime > 600000) score -= 10; // Too slow (more than 10 minutes)
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
    
    // Analyze timing regularity
    const intervals = [];
    for (let i = 1; i < interactions.length; i++) {
      intervals.push(interactions[i].timestamp - interactions[i - 1].timestamp);
    }
    
    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((a, b) => a + Math.pow(b - avgInterval, 2), 0) / intervals.length;
    patterns.regularityScore = Math.min(100, variance / 1000); // Higher variance = more human-like
    
    // Analyze interaction diversity
    const types = new Set(interactions.map(i => i.type));
    patterns.diversityScore = Math.min(100, types.size * 20);
    
    // Overall human-like score
    patterns.humanLikeScore = (patterns.regularityScore + patterns.diversityScore) / 2;
    
    return patterns;
  }

  assessRiskIndicators() {
    const indicators = [];
    
    // Check for automation signs
    if (this.sessionData.behaviorMetrics.suspiciousActivity.length > 0) {
      indicators.push('suspicious_activity_detected');
    }
    
    // Check device consistency
    if (this.sessionData.deviceInfo.screen.width < 800 || this.sessionData.deviceInfo.screen.height < 600) {
      indicators.push('unusual_screen_size');
    }
    
    // Check for missing features
    if (!this.sessionData.deviceInfo.cookieEnabled) {
      indicators.push('cookies_disabled');
    }
    
    if (this.sessionData.deviceInfo.doNotTrack === '1') {
      indicators.push('do_not_track_enabled');
    }
    
    // Check behavior patterns
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
    return 'fsk_toe7ZZBgv8xeEWOie7KffQRfwg8dMSuJRwtOY0Tjdak'; // Demo key
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
    
    // Show loading state
    if (submitBtn) submitBtn.classList.add('loading');
    if (loadingOverlay) loadingOverlay.classList.add('active');
    
    try {
      const response = await this.makeRequest(payload);
      const result = await response.json();
      
      if (response.ok) {
        this.displayResult(result);
        this.clearStoredData();
        
        // Hide loading state after displaying result
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
      
      // Hide loading state on error
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
          'Authorization': `Bearer ${payload.api_key}`,
          'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify(payload),
        credentials: 'same-origin'
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
      errorMessage = '🌐 Network error. Please check your connection.';
    } else if (error.message.includes('timeout')) {
      errorMessage = '⏱️ Request timeout. Please try again.';
    }
    
    this.showNotification(errorMessage, 'error');
    
    // Store data for retry
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
    
    // Animate result appearance
    resultBox.style.opacity = '0';
    resultBox.style.transform = 'translateY(20px)';
    resultBox.classList.add('show');
    
    requestAnimationFrame(() => {
      resultBox.style.transition = 'all 0.4s ease';
      resultBox.style.opacity = '1';
      resultBox.style.transform = 'translateY(0)';
    });
    
    // Scroll to result
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
    
    // Animate in
    setTimeout(() => {
      notification.style.transform = 'translateX(0)';
    }, 100);
    
    // Auto remove
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
        background: var(--glass-bg);
        backdrop-filter: blur(10px);
        border: 1px solid var(--glass-border);
        border-radius: 0.75rem;
        padding: 1rem;
        font-size: 0.8rem;
        color: var(--text-secondary);
        z-index: 9999;
        max-width: 300px;
        min-width: 200px;
        box-shadow: var(--shadow-lg);
        font-family: 'Inter', sans-serif;
      `;
      document.body.appendChild(statusDiv);
    }
    
    const status = userEmail && apiKey !== 'fsk_toe7ZZBgv8xeEWOie7KffQRfwg8dMSuJRwtOY0Tjdak' 
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

  // Public methods for external use
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

// Initialize tracker when DOM is ready
let fraudTracker;

document.addEventListener('DOMContentLoaded', () => {
  fraudTracker = new FraudShieldTracker();
  
  // Expose tracker globally for debugging
  if (typeof window !== 'undefined') {
    window.fraudTracker = fraudTracker;
  }
  
  // Handle page unload
  window.addEventListener('beforeunload', () => {
    if (fraudTracker) {
      fraudTracker.stopIdleTracking();
    }
  });
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
  module.exports = FraudShieldTracker;
}