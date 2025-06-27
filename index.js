// Enhanced index.js with Authentication and Role Management - COMPLETE FIXED VERSION

// Tab Navigation
const tabs = document.querySelectorAll('.tab-btn');
const contents = document.querySelectorAll('.tab-content');

tabs.forEach(btn => {
    btn.addEventListener('click', () => {
        // Check if tab is accessible based on user role
        if (!isTabAccessible(btn.dataset.tab)) {
            showToast('Access restricted', 'You do not have permission to access this section.', 'warning');
            return;
        }

        tabs.forEach(b => b.classList.remove('active'));
        contents.forEach(c => c.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(btn.dataset.tab).classList.add('active');

        // Track tab usage for analytics
        trackTabUsage(btn.dataset.tab);
    });
});

// Authentication and Role Management
class AuthManager {
    static getCurrentUser() {
        try {
            const userData = sessionStorage.getItem('fraudshield_user');
            return userData ? JSON.parse(userData) : null;
        } catch (error) {
            console.error('Failed to parse user data:', error);
            return null;
        }
    }

    static isAuthenticated() {
        const userData = sessionStorage.getItem('fraudshield_user');
        const apiKey = sessionStorage.getItem('fraudshield_api_key');
        return userData && apiKey;
    }

    static hasRole(role) {
        const currentUser = this.getCurrentUser();
        return currentUser && currentUser.user && currentUser.user.role === role;
    }

    static isAdmin() {
        return this.hasRole('admin');
    }

    static getApiKey() {
        return sessionStorage.getItem('fraudshield_api_key');
    }

    static logout() {
        sessionStorage.removeItem('fraudshield_user');
        sessionStorage.removeItem('fraudshield_api_key');
        localStorage.removeItem('fraudshield_remember');
        localStorage.removeItem('fraudshield_email');
        
        showToast('Logged out', 'You have been successfully logged out.', 'info');
        
        setTimeout(() => {
            window.location.href = '/user_auth/pages/login.html';
        }, 1500);
    }

    static init() {
        this.setupUserInterface();
        this.setupRoleBasedAccess();
        this.setupUserMenu();
        this.loadUserProfile();
    }

    static setupUserInterface() {
        if (!window.currentUser) return;

        const user = window.currentUser.user;
        const userName = document.getElementById('userName');
        const userRole = document.getElementById('userRole');
        const userAvatar = document.getElementById('userAvatar');
        const welcomeMessage = document.getElementById('welcomeMessage');
        const dropdownName = document.getElementById('dropdownName');
        const dropdownEmail = document.getElementById('dropdownEmail');

        if (userName) userName.textContent = user.name;
        if (userRole) userRole.textContent = user.role === 'admin' ? 'Administrator' : 'User';
        if (userAvatar) userAvatar.textContent = user.name.charAt(0).toUpperCase();
        if (welcomeMessage) welcomeMessage.textContent = `Welcome back, ${user.name.split(' ')[0]}!`;
        if (dropdownName) dropdownName.textContent = user.name;
        if (dropdownEmail) dropdownEmail.textContent = user.email;
    }

    static setupRoleBasedAccess() {
        if (!window.currentUser) return;

        const user = window.currentUser.user;
        const isAdmin = user.role === 'admin';

        // Logs tab access
        const logsTab = document.getElementById('logsTab');
        const logsAccessCheck = document.getElementById('logsAccessCheck');
        const logControls = document.getElementById('logControls');
        const logContainer = document.getElementById('logContainer');

        // Allow all authenticated users to view logs, but only admins see controls
        if (AuthManager.isAuthenticated()) {
            if (logsAccessCheck) logsAccessCheck.classList.add('hidden');
            if (logContainer) logContainer.classList.remove('hidden');
            if (logsTab) logsTab.style.opacity = '1';
            if (!isAdmin && logControls) logControls.classList.add('hidden');
            if (isAdmin && logControls) logControls.classList.remove('hidden');
        } else {
            // Not authenticated: restrict access
            if (logsAccessCheck) logsAccessCheck.classList.remove('hidden');
            if (logControls) logControls.classList.add('hidden');
            if (logContainer) logContainer.classList.add('hidden');
            if (logsTab) logsTab.style.opacity = '0.6';
        }

        // Settings tab access
        const settingsTab = document.getElementById('settingsTab');
        const settingsAccessCheck = document.getElementById('settingsAccessCheck');
        const settingsGrid = document.getElementById('settingsGrid');

        if (!isAdmin) {
            // Show limited settings for regular users
            this.setupUserSettings();
        } else {
            // Show full admin settings
            this.setupAdminSettings();
        }
    }

    static setupUserSettings() {
        // Regular users see profile and API key management only
        console.log('Setting up user-level settings');
    }

    static setupAdminSettings() {
        const settingsGrid = document.getElementById('settingsGrid');
        if (!settingsGrid) return;

        // Add admin-specific settings cards
        const adminSettingsHTML = `
          <!-- Detection Thresholds -->
          <div class="settings-card">
            <h3>🎯 Detection Thresholds</h3>
            <div class="setting-item">
              <label for="fraudThreshold">Fraud Threshold</label>
              <input type="range" id="fraudThreshold" min="0.5" max="1.0" step="0.1" value="0.7" />
              <span class="threshold-value" id="fraudThresholdValue">0.7</span>
            </div>
            <div class="setting-item">
              <label for="suspiciousThreshold">Suspicious Threshold</label>
              <input type="range" id="suspiciousThreshold" min="0.1" max="0.7" step="0.1" value="0.4" />
              <span class="threshold-value" id="suspiciousThresholdValue">0.4</span>
            </div>
            <button id="saveThresholds" class="primary-btn">💾 Save Thresholds</button>
          </div>

          <!-- System Health -->
          <div class="settings-card">
            <h3>💚 System Status</h3>
            <div class="health-item">
              <span class="health-label">API Status</span>
              <span class="health-status online" id="apiHealth">
                <span class="status-indicator">🟢</span> Online
              </span>
            </div>
            <div class="health-item">
              <span class="health-label">Database</span>
              <span class="health-status" id="dbHealth">
                <span class="status-indicator">🟡</span> Checking...
              </span>
            </div>
            <div class="health-item">
              <span class="health-label">Rule Engine</span>
              <span class="health-status" id="ruleEngineHealth">
                <span class="status-indicator">🟢</span> Active
              </span>
            </div>
            <button id="healthCheck" class="secondary-btn">🔄 Refresh Status</button>
          </div>

          <!-- User Management -->
          <div class="settings-card">
            <h3>👥 User Management</h3>
            <div class="stats-grid">
              <div class="stat-display">
                <span class="stat-number" id="totalUsers">0</span>
                <span class="stat-label">Total Users</span>
              </div>
              <div class="stat-display">
                <span class="stat-number" id="activeUsers">0</span>
                <span class="stat-label">Active Today</span>
              </div>
            </div>
            <button id="manageUsers" class="secondary-btn" href='/admindashboard/user-management.html'>👥 Manage Users</button>
          </div>
        `;

        settingsGrid.insertAdjacentHTML('beforeend', adminSettingsHTML);
        console.log('Added admin-specific settings');
    }

    static setupUserMenu() {
        const userMenuBtn = document.getElementById('userMenuBtn');
        const userDropdown = document.getElementById('userDropdown');
        const logoutBtn = document.getElementById('logoutBtn');

        if (userMenuBtn && userDropdown) {
            userMenuBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                userDropdown.classList.toggle('hidden');
            });

            // Close dropdown when clicking outside
            document.addEventListener('click', () => {
                userDropdown.classList.add('hidden');
            });
        }

        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => {
                this.logout();
            });
        }
    }

    static loadUserProfile() {
        if (!window.currentUser) return;

        const user = window.currentUser.user;
        const profileName = document.getElementById('profileName');
        const profileEmail = document.getElementById('profileEmail');
        const profileCompany = document.getElementById('profileCompany');
        const userApiKey = document.getElementById('userApiKey');

        if (profileName) profileName.value = user.name || '';
        if (profileEmail) profileEmail.value = user.email || '';
        if (profileCompany) profileCompany.value = user.company || '';
        if (userApiKey) userApiKey.textContent = window.apiKey || 'Loading...';
    }
}

// Check tab accessibility based on user role
function isTabAccessible(tabName) {
    // Allow all users (even not logged in) to access 'home' and 'bulk'
    if (tabName === 'home' || tabName === 'bulk') {
        return true;
    }
    // All other tabs require authentication
    return AuthManager.isAuthenticated();
}

// Track tab usage for analytics
function trackTabUsage(tabName) {
    const currentUser = AuthManager.getCurrentUser();
    if (currentUser) {
        console.log(`📊 Tab accessed: ${tabName} by ${currentUser.user.email}`);
        // In production, send to analytics service
    }
}

// Enhanced User Interface Setup
function setupUserInterface() {
    const currentUser = AuthManager.getCurrentUser();
    if (!currentUser) return;

    const user = currentUser.user;
    
    // Update user interface elements
    updateElement('userName', user.name);
    updateElement('userRole', user.role === 'admin' ? 'Administrator' : 'User');
    updateElement('userAvatar', user.name.charAt(0).toUpperCase());
    updateElement('welcomeMessage', `Welcome back, ${user.name.split(' ')[0]}!`);
    updateElement('dropdownName', user.name);
    updateElement('dropdownEmail', user.email);
    updateElement('profileName', user.name, 'value');
    updateElement('profileEmail', user.email, 'value');
    updateElement('profileCompany', user.company || '', 'value');
    updateElement('userApiKey', AuthManager.getApiKey());

    // Setup role-specific content
    setupRoleBasedContent();
}

function updateElement(id, value, property = 'textContent') {
    const element = document.getElementById(id);
    if (element && value !== undefined) {
        element[property] = value;
    }
}

// Setup role-based content and restrictions
function setupRoleBasedContent() {
    const isAdmin = AuthManager.isAdmin();
    
    // Setup logs access
    setupLogsAccess(isAdmin);
    
    // Setup settings access
    setupSettingsAccess(isAdmin);
    
    // Add admin badge if user is admin
    if (isAdmin) {
        addAdminBadge();
    }
}

function setupLogsAccess(isAdmin) {
    const logsAccessCheck = document.getElementById('logsAccessCheck');
    const logControls = document.getElementById('logControls');
    const logContainer = document.getElementById('logContainer');
    const logsTab = document.getElementById('logsTab');

    if (!isAdmin) {
        if (logsAccessCheck) logsAccessCheck.classList.remove('hidden');
        if (logControls) logControls.classList.add('hidden');
        if (logContainer) logContainer.classList.add('hidden');
        if (logsTab) logsTab.style.opacity = '0.6';
    } else {
        if (logsAccessCheck) logsAccessCheck.classList.add('hidden');
        if (logControls) logControls.classList.remove('hidden');
        if (logContainer) logContainer.classList.remove('hidden');
        setupLogControls();
    }
}

function setupSettingsAccess(isAdmin) {
    const settingsGrid = document.getElementById('settingsGrid');
    if (!settingsGrid) return;

    if (isAdmin) {
        addAdminSettings(settingsGrid);
    }
    
    setupSettingsEventListeners(isAdmin);
}

function addAdminSettings(settingsGrid) {
    const adminSettingsHTML = `
        <!-- Detection Thresholds -->
        <div class="settings-card">
            <h3>🎯 Detection Thresholds</h3>
            <div class="setting-item">
                <label for="fraudThreshold">Fraud Threshold</label>
                <input type="range" id="fraudThreshold" min="0.5" max="1.0" step="0.1" value="0.7" />
                <span class="threshold-value" id="fraudThresholdValue">0.7</span>
            </div>
            <div class="setting-item">
                <label for="suspiciousThreshold">Suspicious Threshold</label>
                <input type="range" id="suspiciousThreshold" min="0.1" max="0.7" step="0.1" value="0.4" />
                <span class="threshold-value" id="suspiciousThresholdValue">0.4</span>
            </div>
            <button id="saveThresholds" class="primary-btn">💾 Save Thresholds</button>
        </div>

        <!-- Rule Configuration -->
        <div class="settings-card">
            <h3>⚙️ Detection Rules</h3>
            <div class="rule-toggles">
                <div class="rule-item">
                    <label class="rule-label">
                        <input type="checkbox" id="disposableEmailRule" checked>
                        <span class="rule-name">Disposable Email Detection</span>
                        <span class="rule-weight">Weight: 0.4</span>
                    </label>
                </div>
                <div class="rule-item">
                    <label class="rule-label">
                        <input type="checkbox" id="suspiciousBinRule" checked>
                        <span class="rule-name">Suspicious BIN Check</span>
                        <span class="rule-weight">Weight: 0.5</span>
                    </label>
                </div>
                <div class="rule-item">
                    <label class="rule-label">
                        <input type="checkbox" id="priceTamperingRule" checked>
                        <span class="rule-name">Price Tampering Detection</span>
                        <span class="rule-weight">Weight: 0.5</span>
                    </label>
                </div>
            </div>
            <button id="saveRules" class="primary-btn">💾 Save Rules</button>
        </div>

        <!-- System Health -->
        <div class="settings-card">
            <h3>💚 System Status</h3>
            <div class="health-item">
                <span class="health-label">API Status</span>
                <span class="health-status online" id="apiHealth">
                    <span class="status-indicator">🟢</span> Online
                </span>
            </div>
            <div class="health-item">
                <span class="health-label">Database</span>
                <span class="health-status checking" id="dbHealth">
                    <span class="status-indicator">🟡</span> Checking...
                </span>
            </div>
            <div class="health-item">
                <span class="health-label">Rule Engine</span>
                <span class="health-status online" id="ruleEngineHealth">
                    <span class="status-indicator">🟢</span> Active
                </span>
            </div>
            <button id="healthCheck" class="secondary-btn">🔄 Refresh Status</button>
        </div>

        <!-- User Management -->
        <div class="settings-card">
            <h3>👥 User Management</h3>
            <div class="stats-grid">
                <div class="stat-display">
                    <span class="stat-number" id="totalUsers">Loading...</span>
                    <span class="stat-label">Total Users</span>
                </div>
                <div class="stat-display">
                    <span class="stat-number" id="activeUsers">Loading...</span>
                    <span class="stat-label">Active Today</span>
                </div>
            </div>
            <button id="manageUsers" class="secondary-btn">👥 Manage Users</button>
            <button id="exportUserData" class="secondary-btn">📊 Export Data</button>
        </div>
    `;

    settingsGrid.insertAdjacentHTML('beforeend', adminSettingsHTML);
    setupThresholdListeners();
    loadUserStats();
}

function setupThresholdListeners() {
    const fraudThreshold = document.getElementById('fraudThreshold');
    const suspiciousThreshold = document.getElementById('suspiciousThreshold');
    const fraudValue = document.getElementById('fraudThresholdValue');
    const suspiciousValue = document.getElementById('suspiciousThresholdValue');

    if (fraudThreshold && fraudValue) {
        fraudThreshold.addEventListener('input', (e) => {
            fraudValue.textContent = e.target.value;
        });
    }

    if (suspiciousThreshold && suspiciousValue) {
        suspiciousThreshold.addEventListener('input', (e) => {
            suspiciousValue.textContent = e.target.value;
        });
    }
}

function addAdminBadge() {
    const userRole = document.getElementById('userRole');
    if (userRole && !userRole.querySelector('.admin-badge')) {
        const badge = document.createElement('span');
        badge.className = 'admin-badge';
        badge.textContent = '👑';
        badge.style.marginLeft = '8px';
        badge.title = 'Administrator';
        userRole.appendChild(badge);
    }
}

// Setup event listeners for various components
function setupSettingsEventListeners(isAdmin) {
    // Profile save button
    const saveProfileBtn = document.getElementById('saveProfile');
    if (saveProfileBtn) {
        saveProfileBtn.addEventListener('click', saveProfile);
    }

    // API key copy button
    const copyApiKeyBtn = document.getElementById('copyUserApiKey');
    if (copyApiKeyBtn) {
        copyApiKeyBtn.addEventListener('click', copyApiKey);
    }

    // API key regenerate button
    const regenerateApiKeyBtn = document.getElementById('regenerateApiKey');
    if (regenerateApiKeyBtn) {
        regenerateApiKeyBtn.addEventListener('click', regenerateApiKey);
    }

    if (isAdmin) {
        // Admin-specific event listeners
        setupAdminEventListeners();
    }
}

// FIXED: Complete Admin Event Listeners with proper User Management redirect
function setupAdminEventListeners() {
    // Save thresholds
    const saveThresholdsBtn = document.getElementById('saveThresholds');
    if (saveThresholdsBtn) {
        saveThresholdsBtn.addEventListener('click', saveThresholds);
    }

    // Save rules
    const saveRulesBtn = document.getElementById('saveRules');
    if (saveRulesBtn) {
        saveRulesBtn.addEventListener('click', saveRules);
    }

    // Health check
    const healthCheckBtn = document.getElementById('healthCheck');
    if (healthCheckBtn) {
        healthCheckBtn.addEventListener('click', performHealthCheck);
    }

    // FIXED: User management button with comprehensive redirect logic
    const manageUsersBtn = document.getElementById('manageUsers');
    if (manageUsersBtn) {
        manageUsersBtn.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            console.log('🔄 Manage Users button clicked');
            
            // Check admin privileges
            if (!AuthManager.isAdmin()) {
                showToast('Access Denied', 'Administrator privileges required.', 'error');
                return;
            }
            
            // Show loading feedback
            const originalText = manageUsersBtn.innerHTML;
            manageUsersBtn.innerHTML = '🔄 Loading...';
            manageUsersBtn.disabled = true;
            
            // Multiple redirect strategies
            const redirectStrategies = [
                // Strategy 1: Absolute path from root
                () => { window.location.href = '/admindashboard/user-management.html'; },
                
                // Strategy 2: Relative path
                () => { window.location.href = './admindashboard/user-management.html'; },
                
                // Strategy 3: Without leading slash
                () => { window.location.href = 'admindashboard/user-management.html'; },
                
                // Strategy 4: Full URL
                () => { window.location.href = window.location.origin + '/admindashboard/user-management.html'; },
                
                // Strategy 5: Navigate to parent directory
                () => { window.location.href = '../admindashboard/user-management.html'; }
            ];
            
            // Try each strategy with a delay
            let strategyIndex = 0;
            
            function tryNextStrategy() {
                if (strategyIndex < redirectStrategies.length) {
                    const strategy = redirectStrategies[strategyIndex];
                    console.log(`🔗 Trying redirect strategy ${strategyIndex + 1}/${redirectStrategies.length}`);
                    
                    try {
                        strategy();
                        
                        // If we reach here, the redirect was attempted
                        // Give it a moment to work
                        setTimeout(() => {
                            // If still on same page after 1 second, try next strategy
                            if (window.location.pathname.includes('index.html') || window.location.pathname === '/') {
                                strategyIndex++;
                                tryNextStrategy();
                            }
                        }, 1000);
                        
                    } catch (error) {
                        console.error(`❌ Strategy ${strategyIndex + 1} failed:`, error);
                        strategyIndex++;
                        tryNextStrategy();
                    }
                } else {
                    // All strategies failed
                    console.error('❌ All redirect strategies failed');
                    
                    // Restore button
                    manageUsersBtn.innerHTML = originalText;
                    manageUsersBtn.disabled = false;
                    
                    // Show error with file check instructions
                    showToast(
                        'Navigation Error', 
                        'Could not access User Management page. Please check if the file exists at: /admindashboard/user-management.html', 
                        'error'
                    );
                    
                    // Alternative: Try to open in new tab as last resort
                    setTimeout(() => {
                        const fallbackUrl = '/admindashboard/user-management.html';
                        window.open(fallbackUrl, '_blank');
                        showToast('Info', 'Attempted to open User Management in new tab.', 'info');
                    }, 2000);
                }
            }
            
            // Start trying strategies
            tryNextStrategy();
        });
        
        // Add hover effects for better UX
        manageUsersBtn.addEventListener('mouseenter', function() {
            if (!this.disabled) {
                this.style.transform = 'translateY(-2px)';
                this.style.boxShadow = 'var(--shadow-lg)';
                this.style.transition = 'all 0.2s ease';
            }
        });
        
        manageUsersBtn.addEventListener('mouseleave', function() {
            this.style.transform = '';
            this.style.boxShadow = '';
        });
        
    } else {
        console.warn('⚠️ Manage Users button (#manageUsers) not found in DOM');
        
        // Debug: List all buttons in settings
        const allButtons = document.querySelectorAll('.settings-card button');
        console.log('🔍 Available buttons in settings:', Array.from(allButtons).map(btn => btn.id || btn.textContent));
    }

    // Export user data button
    const exportUserDataBtn = document.getElementById('exportUserData');
    if (exportUserDataBtn) {
        exportUserDataBtn.addEventListener('click', exportUserData);
    }
}

// Alternative direct function for user management (can be called from console for testing)
function openUserManagement() {
    console.log('🔄 Direct user management function called');
    
    // Check admin privileges
    if (!AuthManager.isAdmin()) {
        console.error('❌ Admin privileges required');
        showToast('Access Denied', 'Administrator privileges required.', 'error');
        return;
    }
    
    // List possible paths to try
    const paths = [
        '/admindashboard/user-management.html',
        './admindashboard/user-management.html', 
        'admindashboard/user-management.html',
        window.location.origin + '/admindashboard/user-management.html'
    ];
    
    console.log('🔗 Available paths to try:', paths);
    
    // Try the first path
    const targetPath = paths[0];
    console.log(`🚀 Navigating to: ${targetPath}`);
    
    try {
        window.location.href = targetPath;
    } catch (error) {
        console.error('❌ Navigation failed:', error);
        showToast('Error', `Navigation failed: ${error.message}`, 'error');
    }
}

// User menu functionality
function setupUserMenu() {
    const userMenuBtn = document.getElementById('userMenuBtn');
    const userDropdown = document.getElementById('userDropdown');
    const logoutBtn = document.getElementById('logoutBtn');

    if (userMenuBtn && userDropdown) {
        userMenuBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            userDropdown.classList.toggle('hidden');
        });

        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!userDropdown.contains(e.target) && !userMenuBtn.contains(e.target)) {
                userDropdown.classList.add('hidden');
            }
        });
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            AuthManager.logout();
        });
    }
}

// API functionality
async function loadUserStats() {
    if (!AuthManager.isAdmin()) return;

    try {
        const response = await fetch('http://127.0.0.1:5001/auth/user-stats', {
            headers: {
                'Authorization': `Bearer ${AuthManager.getApiKey()}`
            }
        });

        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                updateElement('totalUsers', data.data.total_users);
                updateElement('activeUsers', data.data.active_today);
            }
        }
    } catch (error) {
        console.error('Failed to load user stats:', error);
        updateElement('totalUsers', 'Error');
        updateElement('activeUsers', 'Error');
    }
}

async function saveProfile() {
    const profileData = {
        name: document.getElementById('profileName').value,
        company: document.getElementById('profileCompany').value
    };

    try {
        showToast('Saving...', 'Updating your profile information.', 'info');
        
        // Simulate API call
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Update session storage
        const currentUser = AuthManager.getCurrentUser();
        if (currentUser) {
            currentUser.user.name = profileData.name;
            currentUser.user.company = profileData.company;
            sessionStorage.setItem('fraudshield_user', JSON.stringify(currentUser));
            setupUserInterface(); // Refresh UI
        }

        showToast('Success', 'Profile updated successfully!', 'success');
    } catch (error) {
        console.error('Failed to save profile:', error);
        showToast('Error', 'Failed to update profile. Please try again.', 'error');
    }
}

async function copyApiKey() {
    const apiKey = AuthManager.getApiKey();
    
    try {
        await navigator.clipboard.writeText(apiKey);
        showToast('Copied', 'API key copied to clipboard!', 'success');
        
        // Update button temporarily
        const btn = document.getElementById('copyUserApiKey');
        const originalText = btn.textContent;
        btn.textContent = '✅ Copied!';
        setTimeout(() => {
            btn.textContent = originalText;
        }, 2000);
    } catch (error) {
        showToast('Error', 'Failed to copy API key.', 'error');
    }
}

async function regenerateApiKey() {
    if (!confirm('Are you sure you want to regenerate your API key? This will invalidate the current key.')) {
        return;
    }

    try {
        showToast('Generating...', 'Creating new API key.', 'info');
        
        // Simulate API call to regenerate key
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        const newApiKey = 'fsk_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        
        sessionStorage.setItem('fraudshield_api_key', newApiKey);
        updateElement('userApiKey', newApiKey);
        
        showToast('Success', 'New API key generated successfully!', 'success');
    } catch (error) {
        console.error('Failed to regenerate API key:', error);
        showToast('Error', 'Failed to generate new API key.', 'error');
    }
}

async function saveThresholds() {
    const fraudThreshold = document.getElementById('fraudThreshold').value;
    const suspiciousThreshold = document.getElementById('suspiciousThreshold').value;

    try {
        showToast('Saving...', 'Updating detection thresholds.', 'info');
        await new Promise(resolve => setTimeout(resolve, 1000));
        showToast('Success', 'Thresholds updated successfully!', 'success');
    } catch (error) {
        showToast('Error', 'Failed to save thresholds.', 'error');
    }
}

async function saveRules() {
    try {
        showToast('Saving...', 'Updating detection rules.', 'info');
        await new Promise(resolve => setTimeout(resolve, 1000));
        showToast('Success', 'Rules updated successfully!', 'success');
    } catch (error) {
        showToast('Error', 'Failed to save rules.', 'error');
    }
}

async function performHealthCheck() {
    try {
        const btn = document.getElementById('healthCheck');
        btn.disabled = true;
        btn.textContent = '🔄 Checking...';

        // Check API health
        const response = await fetch('http://127.0.0.1:5000/health');
        const dbHealth = document.getElementById('dbHealth');
        
        if (response.ok) {
            dbHealth.innerHTML = '<span class="status-indicator">🟢</span> Online';
            dbHealth.className = 'health-status online';
        } else {
            dbHealth.innerHTML = '<span class="status-indicator">🔴</span> Offline';
            dbHealth.className = 'health-status offline';
        }

        showToast('Health Check', 'System health check completed.', 'info');
    } catch (error) {
        const dbHealth = document.getElementById('dbHealth');
        dbHealth.innerHTML = '<span class="status-indicator">🔴</span> Error';
        dbHealth.className = 'health-status offline';
        
        showToast('Error', 'Health check failed.', 'error');
    } finally {
        const btn = document.getElementById('healthCheck');
        btn.disabled = false;
        btn.textContent = '🔄 Refresh Status';
    }
}

// Export user data function
async function exportUserData() {
    if (!AuthManager.isAdmin()) {
        showToast('Access Denied', 'Administrator privileges required.', 'error');
        return;
    }
    
    try {
        showToast('Exporting...', 'Preparing user data export.', 'info');
        
        // Create sample CSV data (replace with real API call in production)
        const userData = [
            ['Name', 'Email', 'Role', 'Company', 'Created At', 'Last Login', 'Status'],
            ['John Doe', 'john@example.com', 'admin', 'TechCorp', '2025-06-20', '2025-06-26', 'Active'],
            ['Jane Smith', 'jane@company.com', 'user', 'StartupInc', '2025-06-18', '2025-06-25', 'Active'],
            ['Bob Johnson', 'bob@business.org', 'user', 'Business Solutions', '2025-06-10', '2025-06-15', 'Inactive']
        ];
        
        // Convert to CSV
        const csvContent = userData.map(row => 
            row.map(field => `"${field}"`).join(',')
        ).join('\n');
        
        // Create and download file
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        
        link.setAttribute('href', url);
        link.setAttribute('download', `fraudshield_users_${new Date().toISOString().split('T')[0]}.csv`);
        link.style.visibility = 'hidden';
        
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        URL.revokeObjectURL(url);
        
        showToast('Success', 'User data exported successfully!', 'success');
        
    } catch (error) {
        console.error('Export failed:', error);
        showToast('Error', 'Failed to export user data.', 'error');
    }
}

// Log controls for admin
function setupLogControls() {
    const clearLogsBtn = document.getElementById('clearLogs');
    const exportLogsBtn = document.getElementById('exportLogs');

    if (clearLogsBtn) {
        clearLogsBtn.addEventListener('click', () => {
            if (confirm('Are you sure you want to clear all logs?')) {
                showToast('Cleared', 'Activity logs have been cleared.', 'info');
            }
        });
    }

    if (exportLogsBtn) {
        exportLogsBtn.addEventListener('click', () => {
            showToast('Export', 'Logs exported successfully.', 'success');
        });
    }
}

// Enhanced Toast Notification System
function showToast(title, message, type = 'info') {
    // Remove existing toasts of the same type to prevent spam
    const existingToasts = document.querySelectorAll(`.toast.${type}`);
    existingToasts.forEach(toast => toast.remove());
    
    // Create toast container if it doesn't exist
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'toast-container';
        container.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            max-width: 400px;
            pointer-events: none;
        `;
        document.body.appendChild(container);
    }
    
    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.style.cssText = `
        background: white;
        border-radius: 12px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        padding: 16px;
        margin-bottom: 12px;
        border-left: 4px solid;
        animation: slideIn 0.3s ease-out;
        pointer-events: auto;
        max-width: 100%;
        word-wrap: break-word;
    `;
    
    // Set border color based on type
    const colors = {
        success: '#10b981',
        error: '#ef4444',
        warning: '#f59e0b',
        info: '#3b82f6'
    };
    toast.style.borderLeftColor = colors[type] || colors.info;
    
    // Create toast content
    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };
    
    toast.innerHTML = `
        <div style="display: flex; align-items: flex-start; gap: 12px;">
            <span style="font-size: 18px; flex-shrink: 0;">${icons[type] || icons.info}</span>
            <div style="flex: 1;">
                <div style="font-weight: 600; color: #1f2937; margin-bottom: 4px;">${title}</div>
                <div style="color: #6b7280; font-size: 14px;">${message}</div>
            </div>
            <button onclick="this.parentElement.parentElement.remove()" 
                    style="background: none; border: none; color: #9ca3af; cursor: pointer; padding: 4px; border-radius: 4px; flex-shrink: 0;"
                    title="Close">✕</button>
        </div>
    `;
    
    // Add to container
    container.appendChild(toast);
    
    // Auto remove after delay
    const delay = type === 'error' ? 8000 : 5000;
    setTimeout(() => {
        if (toast.parentNode) {
            toast.style.animation = 'slideOut 0.3s ease-in forwards';
            setTimeout(() => toast.remove(), 300);
        }
    }, delay);
    
    // Add CSS animations if not already added
    if (!document.getElementById('toast-animations')) {
        const style = document.createElement('style');
        style.id = 'toast-animations';
        style.textContent = `
            @keyframes slideIn {
                from { opacity: 0; transform: translateX(100%); }
                to { opacity: 1; transform: translateX(0); }
            }
            @keyframes slideOut {
                from { opacity: 1; transform: translateX(0); }
                to { opacity: 0; transform: translateX(100%); }
            }
        `;
        document.head.appendChild(style);
    }
}

// ---------------------------------------------------------------------------
// FIXED Bulk-Upload with Proper Button State Management
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  // DOM refs
  const fileInput       = document.getElementById('bulkFile');
  const submitBtn       = document.getElementById('bulkSubmit');
  const progressOuter   = document.querySelector('.upload-progress-bar');
  const progressInner   = document.querySelector('.upload-progress-bar-inner');
  const bulkResultsBox  = document.getElementById('bulkResults');
  const fileInfo        = document.getElementById('fileInfo');
  const fileName        = document.getElementById('fileName');
  const fileSize        = document.getElementById('fileSize');
  const uploadBox       = document.getElementById('uploadBox');

  // Hide progress bar initially
  if (progressOuter) progressOuter.classList.add('hidden');

  // Validate file function
  function validateFile(file) {
    if (!file) {
      return { valid: false, message: "No file selected" };
    }

    // Check file extension
    const allowedExtensions = ['csv', 'json', 'xlsx', 'xls', 'txt'];
    const extension = file.name.split('.').pop().toLowerCase();
    
    if (!allowedExtensions.includes(extension)) {
      return { 
        valid: false, 
        message: `File type not supported. Allowed: ${allowedExtensions.join(', ')}` 
      };
    }

    // Check file size (16MB limit)
    const maxSize = 16 * 1024 * 1024;
    if (file.size > maxSize) {
      return { 
        valid: false, 
        message: `File too large. Maximum: 16MB. Your file: ${(file.size / (1024*1024)).toFixed(1)}MB` 
      };
    }

    if (file.size === 0) {
      return { valid: false, message: "File is empty" };
    }

    return { valid: true, message: "File is valid" };
  }

  // Format file size for display
  function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  // Update button state and text
  function updateButtonState(file) {
    if (!file) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Select a file first';
      submitBtn.style.cursor = 'not-allowed';
      submitBtn.style.opacity = '0.6';
      return;
    }

    const validation = validateFile(file);
    
    if (validation.valid) {
      // Enable button for valid files
      submitBtn.disabled = false;
      submitBtn.innerHTML = `
        <span class="btn-icon">🔍</span>
        <span class="btn-text">Analyze ${file.name}</span>
      `;
      submitBtn.style.cursor = 'pointer';
      submitBtn.style.opacity = '1';
      submitBtn.style.background = 'linear-gradient(135deg, var(--primary), var(--primary-light))';
      
      // Show file info
      if (fileName) fileName.textContent = file.name;
      if (fileSize) fileSize.textContent = formatFileSize(file.size);
      if (fileInfo) fileInfo.classList.remove('hidden');
      
    } else {
      // Disable button for invalid files
      submitBtn.disabled = true;
      submitBtn.innerHTML = `
        <span class="btn-icon">❌</span>
        <span class="btn-text">${validation.message}</span>
      `;
      submitBtn.style.cursor = 'not-allowed';
      submitBtn.style.opacity = '0.6';
      submitBtn.style.background = '#dc2626';
      
      // Hide file info
      if (fileInfo) fileInfo.classList.add('hidden');
    }
  }

  // File input change handler
  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    updateButtonState(file);
    
    // Clear previous results
    if (bulkResultsBox) bulkResultsBox.innerHTML = '';
  });

  // Drag and drop functionality
  if (uploadBox) {
    uploadBox.addEventListener('dragover', (e) => {
      e.preventDefault();
      uploadBox.style.borderColor = 'var(--primary)';
      uploadBox.style.backgroundColor = 'rgba(37, 99, 235, 0.05)';
    });

    uploadBox.addEventListener('dragleave', (e) => {
      e.preventDefault();
      uploadBox.style.borderColor = 'var(--gray-300)';
      uploadBox.style.backgroundColor = '';
    });

    uploadBox.addEventListener('drop', (e) => {
      e.preventDefault();
      uploadBox.style.borderColor = 'var(--gray-300)';
      uploadBox.style.backgroundColor = '';
      
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        fileInput.files = files;
        const event = new Event('change', { bubbles: true });
        fileInput.dispatchEvent(event);
      }
    });
  }

  // Initialize button state
  updateButtonState(null);

  // --- Helper to render server results ------------------------------------
  function renderResults(results, summary = null) {
    const ok   = results.filter(r => r.decision === 'not_fraud').length;
    const sus  = results.filter(r => r.decision === 'suspicious').length;
    const bad  = results.filter(r => r.decision === 'fraud').length;
    const errors = results.filter(r => r.decision === 'error').length;

    const summaryText = summary ? `
      <div style="margin-bottom: 16px; padding: 12px; background: #f1f5f9; border-radius: 8px; font-size: 0.9rem;">
        📁 <strong>${summary.filename || 'Unknown file'}</strong><br>
        ⏱️ Processing time: ${summary.processing_time_seconds || 0}s<br>
        📊 Total records: ${summary.total_records || results.length}
      </div>
    ` : '';

    bulkResultsBox.innerHTML = `
      ${summaryText}
      <div class="summary-box">
        <b>Analysis Complete</b>
        Total transactions: ${results.length}<br>
        <span style="color:#059669;">✅ Safe: ${ok}</span><br>
        <span style="color:#d97706;">⚠️ Suspicious: ${sus}</span><br>
        <span style="color:#dc2626;">❌ Fraud: ${bad}</span><br>
        ${errors > 0 ? `<span style="color:#6b7280;">❓ Errors: ${errors}</span><br>` : ''}
        <br>
        <button id="dlCsv" class="secondary-btn">📥 Download Results</button>
      </div>
    `;

    // CSV download functionality
    document.getElementById('dlCsv').onclick = () => {
      try {
        const headers = Object.keys(results[0] || {});
        const csv = [
          headers.join(','),
          ...results.map(r => headers.map(h => {
            let value = r[h];
            if (Array.isArray(value)) {
              value = value.join(';');
            }
            if (typeof value === 'string' && (value.includes(',') || value.includes('"'))) {
              value = `"${value.replace(/"/g, '""')}"`;
            }
            return value || '';
          }).join(','))
        ].join('\n');
        
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href = url;
        a.download = `fraudshield_results_${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      } catch (error) {
        alert('Error generating CSV: ' + error.message);
      }
    };
  }

  // --- Enhanced table rendering ----------------------
  function renderTable(results) {
    let sortKey = null;
    let sortAsc = true;
    let sortedResults = [...results];

    const headers = [
      { label: "#", key: null },
      { label: "Email", key: "email" },
      { label: "Card", key: "card_number" },
      { label: "IP", key: "ip" },
      { label: "Fingerprint", key: "fingerprint" },
      { label: "Price", key: "price" },
      { label: "Decision", key: "decision" },
      { label: "Score", key: "fraud_score" },
      { label: "Triggered", key: "triggered_rules" }
    ];

    const tableContainer = document.createElement('div');
    tableContainer.className = 'table-container';
    
    const table = document.createElement('table');
    table.classList.add('bulk-table');

    // Table Head
    const thead = table.createTHead();
    const headRow = thead.insertRow();
    headers.forEach((h) => {
      const th = document.createElement('th');
      th.textContent = h.label;
      if (h.key) {
        th.style.cursor = "pointer";
        th.title = "Click to sort by " + h.label;
        th.classList.add('sortable');
        th.onclick = () => {
          // Remove previous sort indicators
          document.querySelectorAll('th.sortable').forEach(header => {
            header.classList.remove('sort-asc', 'sort-desc');
          });
          
          if (sortKey === h.key) {
            sortAsc = !sortAsc;
          } else {
            sortKey = h.key;
            sortAsc = true;
          }
          
          // Add sort indicator
          th.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
          
          sortedResults.sort((a, b) => {
            let va = a[h.key], vb = b[h.key];
            
            if (h.key === "fraud_score" || h.key === "price") {
              va = parseFloat(va) || 0;
              vb = parseFloat(vb) || 0;
            } else if (Array.isArray(va)) {
              va = va.join(",");
              vb = Array.isArray(vb) ? vb.join(",") : "";
            } else {
              va = String(va || "").toLowerCase();
              vb = String(vb || "").toLowerCase();
            }
            
            if (va < vb) return sortAsc ? -1 : 1;
            if (va > vb) return sortAsc ? 1 : -1;
            return 0;
          });
          
          renderBody();
        };
      }
      headRow.appendChild(th);
    });

    // Table Body
    const tbody = table.createTBody();
    function renderBody() {
      tbody.innerHTML = "";
      sortedResults.forEach((r, idx) => {
        const row = tbody.insertRow();
        row.className = `decision-row decision-${r.decision}`;
        
        const triggeredRules = Array.isArray(r.triggered_rules) 
          ? r.triggered_rules.join(", ") 
          : (r.triggered_rules || "-");
        
        row.innerHTML = `
          <td class="center">${idx + 1}</td>
          <td title="${r.email || ''}">${r.email || '-'}</td>
          <td title="${r.card_number || ''}">${r.card_number || '-'}</td>
          <td title="${r.ip || ''}">${r.ip || '-'}</td>
          <td title="${r.fingerprint || ''}">${r.fingerprint || '-'}</td>
          <td class="center">${r.price || '0'}</td>
          <td class="center">
            <span class="status-indicator status-${r.decision === 'not_fraud' ? 'safe' : r.decision}">
              ${r.decision || 'unknown'}
            </span>
          </td>
          <td class="center"><strong>${r.fraud_score || '0'}</strong></td>
          <td title="${triggeredRules}">${triggeredRules}</td>
        `;
      });
    }
    renderBody();

    tableContainer.appendChild(table);
    return tableContainer;
  }

  // --- Main form submission handler -------------------
  submitBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    
    const file = fileInput.files[0];
    
    // Double-check validation
    const validation = validateFile(file);
    if (!validation.valid) {
      alert(validation.message);
      return;
    }
    
    // Reset UI
    bulkResultsBox.innerHTML = '';
    if (progressOuter) progressOuter.classList.remove('hidden');
    if (progressInner) progressInner.style.width = '0%';
    
    // Update button to loading state
    submitBtn.disabled = true;
    submitBtn.innerHTML = `
      <span class="loading"></span>
      <span class="btn-text">Processing...</span>
    `;

    const formData = new FormData();
    formData.append('file', file);

    try {
      console.log('Sending request to bulk-check API...');
      
      const response = await fetch('http://127.0.0.1:5000/bulk-check', {
        method: 'POST',
        body: formData,
      });

      if (progressInner) progressInner.style.width = '50%';

      if (!response.ok) {
        const errorText = await response.text();
        console.error('API Error:', response.status, errorText);
        throw new Error(`Server error (${response.status}): ${errorText}`);
      }

      const responseData = await response.json();
      console.log('API Response:', responseData);

      if (progressInner) progressInner.style.width = '100%';

      if (!responseData.success) {
        throw new Error(responseData.error || 'API returned failure status');
      }

      const results = responseData.data?.results;
      const summary = responseData.data?.summary;

      if (!results || !Array.isArray(results)) {
        console.error('Invalid response structure:', responseData);
        throw new Error('Invalid response format: results not found');
      }

      if (results.length === 0) {
        bulkResultsBox.innerHTML = '<div style="color: #6b7280; padding: 16px; text-align: center;">ℹ️ No data found in the uploaded file.</div>';
        return;
      }

      console.log(`Processing ${results.length} results...`);

      // Render results
      bulkResultsBox.innerHTML = "<h3>Fraud Analysis Results</h3>";
      bulkResultsBox.appendChild(renderTable(results));

      // Add summary after table
      setTimeout(() => {
        renderResults(results, summary);
        bulkResultsBox.appendChild(renderTable(results));
      }, 100);

    } catch (err) {
      console.error('Request failed:', err);
      if (progressInner) progressInner.style.width = '0%';
      
      let errorMessage = 'Unknown error occurred';
      if (err.message) {
        errorMessage = err.message;
      } else if (err.name === 'TypeError' && err.message.includes('fetch')) {
        errorMessage = 'Cannot connect to server. Make sure the Flask API is running on http://127.0.0.1:5000';
      }

      bulkResultsBox.innerHTML = `
        <div style="color: #dc2626; padding: 20px; text-align: center; background: #fee2e2; border-radius: 8px; margin: 16px 0;">
          <strong>❌ Error:</strong><br>
          ${errorMessage}
          <br><br>
          <small style="color: #7f1d1d;">
            Check the browser console (F12) for more details.
          </small>
        </div>
      `;
    } finally {
      // Reset button state
      setTimeout(() => {
        if (progressOuter) progressOuter.classList.add('hidden');
        updateButtonState(fileInput.files[0]); // Restore proper button state
      }, 1000);
    }
  });

  // Utility function for tab switching
  window.switchToTab = function(tabName) {
    const tabBtn = document.querySelector(`[data-tab="${tabName}"]`);
    if (tabBtn) {
      tabBtn.click();
    }
  };
});

// At the end of your file or after DOMContentLoaded
document.addEventListener('DOMContentLoaded', function() {
  // Set window.currentUser and window.apiKey from sessionStorage if available
  const userData = sessionStorage.getItem('fraudshield_user');
  const apiKey = sessionStorage.getItem('fraudshield_api_key');
  if (userData) window.currentUser = JSON.parse(userData);
  if (apiKey) window.apiKey = apiKey;

  AuthManager.init();
  
  // Make functions globally available for console testing
  window.openUserManagement = openUserManagement;
  window.AuthManager = AuthManager;
  window.showToast = showToast;
  
  console.log('🔧 FraudShield Dashboard Loaded');
  console.log('🔍 Debug functions available: openUserManagement(), showToast()');
  if (AuthManager.isAdmin()) {
    console.log('👑 Admin user detected - all features available');
    console.log('🔗 To test user management: openUserManagement()');
  }
});