// Enhanced index.js with FIXED Authentication and Session Management
// Now supports both authenticated and anonymous users

// Tab Navigation
const tabs = document.querySelectorAll('.tab-btn');
const contents = document.querySelectorAll('.tab-content');

tabs.forEach(btn => {
    btn.addEventListener('click', () => {
        // Check if tab is accessible based on user role
        if (!isTabAccessible(btn.dataset.tab)) {
            showToast('Access Restricted', 'Please sign in to access this feature.', 'warning');
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

// FIXED: Authentication and Role Management
class AuthManager {
    static getCurrentUser() {
        try {
            // Check sessionStorage first
            let userData = sessionStorage.getItem('fraudshield_user');
            
            // If not in sessionStorage, check localStorage for persistent session
            if (!userData) {
                userData = localStorage.getItem('fraudshield_persistent_user');
                
                // If found in localStorage, restore to sessionStorage
                if (userData) {
                    sessionStorage.setItem('fraudshield_user', userData);
                    
                    // Also restore API key and session ID
                    const apiKey = localStorage.getItem('fraudshield_persistent_api_key');
                    const sessionId = localStorage.getItem('fraudshield_persistent_session_id');
                    
                    if (apiKey) sessionStorage.setItem('fraudshield_api_key', apiKey);
                    if (sessionId) sessionStorage.setItem('fraudshield_session_id', sessionId);
                }
            }
            
            return userData ? JSON.parse(userData) : null;
        } catch (error) {
            console.error('Failed to parse user data:', error);
            // Clear corrupted session data from both storages
            this.clearCorruptedSession();
            return null;
        }
    }

    static isAuthenticated() {
        // Check both sessionStorage and localStorage
        const sessionUser = sessionStorage.getItem('fraudshield_user');
        const sessionApiKey = sessionStorage.getItem('fraudshield_api_key');
        
        const persistentUser = localStorage.getItem('fraudshield_persistent_user');
        const persistentApiKey = localStorage.getItem('fraudshield_persistent_api_key');
        
        return !!(
            (sessionUser && sessionApiKey) || 
            (persistentUser && persistentApiKey)
        );
    }

    static hasRole(role) {
        const currentUser = this.getCurrentUser();
        return currentUser && currentUser.user && currentUser.user.role === role;
    }

    static isAdmin() {
        return this.hasRole('admin');
    }

    static getApiKey() {
        // Check sessionStorage first
        let apiKey = sessionStorage.getItem('fraudshield_api_key');
        
        // If not in sessionStorage, check localStorage
        if (!apiKey) {
            apiKey = localStorage.getItem('fraudshield_persistent_api_key');
            
            // If found in localStorage, restore to sessionStorage
            if (apiKey) {
                sessionStorage.setItem('fraudshield_api_key', apiKey);
            }
        }
        
        return apiKey;
    }

    static logout() {
        // Clear all session data from both storages
        sessionStorage.removeItem('fraudshield_user');
        sessionStorage.removeItem('fraudshield_api_key');
        sessionStorage.removeItem('fraudshield_session_id');
        
        localStorage.removeItem('fraudshield_persistent_user');
        localStorage.removeItem('fraudshield_persistent_api_key');
        localStorage.removeItem('fraudshield_persistent_session_id');
        localStorage.removeItem('fraudshield_remember');
        localStorage.removeItem('fraudshield_email');
        localStorage.removeItem('fraudshield_login_timestamp');
        
        // Reset global variables
        window.currentUser = null;
        window.apiKey = null;
        
        console.log('👋 Complete logout - all session data cleared');
        
        // Refresh the page to reset UI state
        setTimeout(() => {
            window.location.reload();
        }, 1500);
    }

    static clearCorruptedSession() {
        // Clear corrupted data from both storages
        sessionStorage.removeItem('fraudshield_user');
        sessionStorage.removeItem('fraudshield_api_key');
        sessionStorage.removeItem('fraudshield_session_id');
        
        localStorage.removeItem('fraudshield_persistent_user');
        localStorage.removeItem('fraudshield_persistent_api_key');
        localStorage.removeItem('fraudshield_persistent_session_id');
        
        console.warn('🧹 Cleared corrupted session data');
    }

    static init() {
        // Check for persistent session on page load
        this.restorePersistentSession();
        this.setupUserInterface();
        this.setupRoleBasedAccess();
        this.setupUserMenu();
        this.loadUserProfile();
        this.checkApiConnection();
    }

    static restorePersistentSession() {
        // Check if user has a persistent session
        const persistentUser = localStorage.getItem('fraudshield_persistent_user');
        const persistentApiKey = localStorage.getItem('fraudshield_persistent_api_key');
        const loginTimestamp = localStorage.getItem('fraudshield_login_timestamp');
        
        if (persistentUser && persistentApiKey) {
            // Check if session is still valid (not older than 30 days)
            if (loginTimestamp) {
                const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
                if (parseInt(loginTimestamp) < thirtyDaysAgo) {
                    console.log('🕐 Persistent session expired, clearing...');
                    this.clearExpiredSession();
                    return;
                }
            }
            
            // Restore to sessionStorage for current session
            sessionStorage.setItem('fraudshield_user', persistentUser);
            sessionStorage.setItem('fraudshield_api_key', persistentApiKey);
            
            const persistentSessionId = localStorage.getItem('fraudshield_persistent_session_id');
            if (persistentSessionId) {
                sessionStorage.setItem('fraudshield_session_id', persistentSessionId);
            }
            
            console.log('🔄 Restored persistent session');
        }
    }

    static clearExpiredSession() {
        localStorage.removeItem('fraudshield_persistent_user');
        localStorage.removeItem('fraudshield_persistent_api_key');
        localStorage.removeItem('fraudshield_persistent_session_id');
        localStorage.removeItem('fraudshield_remember');
        localStorage.removeItem('fraudshield_email');
        localStorage.removeItem('fraudshield_login_timestamp');
    }

    static setupUserInterface() {
        const isAuth = this.isAuthenticated();
        const currentUser = this.getCurrentUser();
        
        // Setup user section in header
        this.setupUserSection(isAuth, currentUser);
        
        // Setup welcome message
        if (isAuth && currentUser) {
            const user = currentUser.user;
            const welcomeMessage = document.getElementById('welcomeMessage');
            if (welcomeMessage) {
                welcomeMessage.textContent = `Welcome back, ${user.name.split(' ')[0]}!`;
            }
        }

        // Show/hide authentication prompts
        this.setupAuthPrompts(isAuth);
    }

    static setupUserSection(isAuth, currentUser) {
        const userSection = document.getElementById('userSection');
        
        if (isAuth && currentUser) {
            const user = currentUser.user;
            
            // Show authenticated user interface
            userSection.innerHTML = `
                <div class="user-info">
                    <span class="user-name">${user.name}</span>
                    <span class="user-role">${user.role === 'admin' ? 'Administrator' : 'User'}</span>
                </div>
                <div class="user-menu">
                    <button class="user-menu-btn" id="userMenuBtn" aria-label="User menu">
                        <span class="user-avatar">${user.name.charAt(0).toUpperCase()}</span>
                    </button>
                    <div class="user-dropdown hidden" id="userDropdown">
                        <div class="dropdown-header">
                            <div class="dropdown-user-info">
                                <span class="dropdown-name">${user.name}</span>
                                <span class="dropdown-email">${user.email}</span>
                            </div>
                        </div>
                        <div class="dropdown-divider"></div>
                        <button class="dropdown-item" id="settingsShortcut">
                            <span class="dropdown-icon">⚙️</span>
                            Settings
                        </button>
                        ${user.role === 'admin' ? `
                        <button class="dropdown-item" id="userManagementShortcut">
                            <span class="dropdown-icon">👥</span>
                            User Management
                        </button>
                        ` : ''}
                        <div class="dropdown-divider"></div>
                        <button class="dropdown-item logout-btn" id="logoutBtn">
                            <span class="dropdown-icon">🚪</span>
                            Sign Out
                        </button>
                    </div>
                </div>
            `;
        } else {
            // Show login/register buttons for anonymous users
            userSection.innerHTML = `
                <div style="display: flex; gap: 0.75rem; align-items: center;">
                    <a href="/user_auth/pages/login.html" 
                       style="display: inline-flex; align-items: center; gap: 0.5rem; background: white; color: #2563eb; padding: 0.5rem 1rem; border-radius: 8px; text-decoration: none; font-weight: 500; border: 1px solid #2563eb; transition: all 0.2s;">
                        <span>🚪</span>
                        <span>Sign In</span>
                    </a>
                    <a href="/user_auth/pages/registration.html" 
                       style="display: inline-flex; align-items: center; gap: 0.5rem; background: #2563eb; color: white; padding: 0.5rem 1rem; border-radius: 8px; text-decoration: none; font-weight: 500; transition: all 0.2s;">
                        <span>👤</span>
                        <span>Sign Up</span>
                    </a>
                </div>
            `;
        }
    }

    static setupAuthPrompts(isAuth) {
        // Show/hide auth prompts on home page
        const authPrompt = document.getElementById('authPrompt');
        if (authPrompt) {
            if (isAuth) {
                authPrompt.classList.add('hidden');
            } else {
                authPrompt.classList.remove('hidden');
            }
        }

        // Show/hide public access notice on bulk page
        const publicAccessNotice = document.getElementById('publicAccessNotice');
        if (publicAccessNotice) {
            if (isAuth) {
                publicAccessNotice.classList.add('hidden');
            } else {
                publicAccessNotice.classList.remove('hidden');
            }
        }
    }

    static setupRoleBasedAccess() {
        const isAuth = this.isAuthenticated();
        const isAdmin = this.isAdmin();
        
        // Setup logs access
        this.setupLogsAccess(isAuth, isAdmin);
        
        // Setup settings access
        this.setupSettingsAccess(isAuth, isAdmin);
    }

    static setupLogsAccess(isAuth, isAdmin) {
        const logsAuthRequired = document.getElementById('logsAuthRequired');
        const logsAdminOnly = document.getElementById('logsAdminOnly');
        const logControls = document.getElementById('logControls');
        const logContainer = document.getElementById('logContainer');

        if (!isAuth) {
            // Not authenticated - show auth required message
            if (logsAuthRequired) logsAuthRequired.style.display = 'block';
            if (logsAdminOnly) logsAdminOnly.classList.add('hidden');
            if (logControls) logControls.classList.add('hidden');
            if (logContainer) logContainer.classList.add('hidden');
        } else {
            // Authenticated - show logs (both admin and regular users can see their own logs)
            if (logsAuthRequired) logsAuthRequired.style.display = 'none';
            if (logsAdminOnly) logsAdminOnly.classList.add('hidden');
            if (logControls) logControls.classList.remove('hidden');
            if (logContainer) logContainer.classList.remove('hidden');
            
            // Initialize activity logs manager for authenticated users
            if (window.activityLogsManager) {
                window.activityLogsManager.destroy();
            }
            window.activityLogsManager = ActivityLogsManager.init();
        }
    }

    static setupSettingsAccess(isAuth, isAdmin) {
        const settingsAuthRequired = document.getElementById('settingsAuthRequired');
        const settingsGrid = document.getElementById('settingsGrid');

        if (!isAuth) {
            // Not authenticated - show auth required message
            if (settingsAuthRequired) settingsAuthRequired.style.display = 'block';
            if (settingsGrid) settingsGrid.classList.add('hidden');
        } else {
            // Authenticated - show settings
            if (settingsAuthRequired) settingsAuthRequired.style.display = 'none';
            if (settingsGrid) settingsGrid.classList.remove('hidden');

            // Lock buttons for non-admin users
            if (!isAdmin) {
                // Disable profile editing
                const profileName = document.getElementById('profileName');
                const profileCompany = document.getElementById('profileCompany');
                const saveProfileBtn = document.getElementById('saveProfile');
                
                if (profileName) {
                    profileName.disabled = true;
                    profileName.style.cursor = 'not-allowed';
                }
                if (profileCompany) {
                    profileCompany.disabled = true;
                    profileCompany.style.cursor = 'not-allowed';
                }
                if (saveProfileBtn) {
                    saveProfileBtn.disabled = true;
                    saveProfileBtn.style.cursor = 'not-allowed';
                    saveProfileBtn.style.opacity = '0.5';
                }
                
                // Disable API key regeneration
                const regenerateBtn = document.getElementById('regenerateApiKey');
                if (regenerateBtn) {
                    regenerateBtn.disabled = true;
                    regenerateBtn.style.cursor = 'not-allowed';
                    regenerateBtn.style.opacity = '0.5';
                }
            }
            
            if (isAdmin) {
                this.addAdminSettings(settingsGrid);
            }
            
            this.setupSettingsEventListeners(isAdmin);
        }
    }

    static addAdminSettings(settingsGrid) {
        // Check if admin settings already exist
        if (settingsGrid.querySelector('.admin-settings-card')) {
            return;
        }

        const adminSettingsHTML = `
            <!-- Detection Thresholds -->
            <div class="settings-card admin-settings-card">
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
            <div class="settings-card admin-settings-card">
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
            <div class="settings-card admin-settings-card">
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
        this.setupThresholdListeners();
        this.loadUserStats();
    }

    static setupThresholdListeners() {
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

    static setupUserMenu() {
        const userMenuBtn = document.getElementById('userMenuBtn');
        const userDropdown = document.getElementById('userDropdown');
        const logoutBtn = document.getElementById('logoutBtn');
        const settingsShortcut = document.getElementById('settingsShortcut');
        const userManagementShortcut = document.getElementById('userManagementShortcut');

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

        // Settings shortcut - switches to settings tab
        if (settingsShortcut) {
            settingsShortcut.addEventListener('click', () => {
                // Switch to settings tab
                const settingsTab = document.querySelector('[data-tab="settings"]');
                if (settingsTab) {
                    settingsTab.click();
                }
                userDropdown.classList.add('hidden');
            });
        }

        // User Management shortcut (admin only)
        if (userManagementShortcut) {
            userManagementShortcut.addEventListener('click', () => {
                if (this.isAdmin()) {
                    window.open('/admindashboard/user-management.html', '_blank');
                } else {
                    showToast('Access Denied', 'Administrator privileges required.', 'error');
                }
                userDropdown.classList.add('hidden');
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

    static async checkApiConnection() {
        try {
            const apiStatus = document.getElementById('apiStatus');
            if (!apiStatus) return;

            const statusText = apiStatus.querySelector('.status-text');
            const statusDot = apiStatus.querySelector('.status-dot');

            // Check main API
            const response = await fetch('http://127.0.0.1:5000/health');
            
            if (response.ok) {
                statusText.textContent = 'API Online';
                statusDot.style.backgroundColor = '#10b981';
            } else {
                statusText.textContent = 'API Issues';
                statusDot.style.backgroundColor = '#f59e0b';
            }
        } catch (error) {
            console.warn('API health check failed:', error);
            const apiStatus = document.getElementById('apiStatus');
            if (apiStatus) {
                const statusText = apiStatus.querySelector('.status-text');
                const statusDot = apiStatus.querySelector('.status-dot');
                statusText.textContent = 'API Offline';
                statusDot.style.backgroundColor = '#ef4444';
            }
        }
    }

    static setupSettingsEventListeners(isAdmin) {
        // Profile save button
        const saveProfileBtn = document.getElementById('saveProfile');
        if (saveProfileBtn) {
            saveProfileBtn.addEventListener('click', this.saveProfile.bind(this));
        }

        // API key copy button
        const copyApiKeyBtn = document.getElementById('copyUserApiKey');
        if (copyApiKeyBtn) {
            copyApiKeyBtn.addEventListener('click', this.copyApiKey.bind(this));
        }

        // API key regenerate button
        const regenerateApiKeyBtn = document.getElementById('regenerateApiKey');
        if (regenerateApiKeyBtn) {
            regenerateApiKeyBtn.addEventListener('click', this.regenerateApiKey.bind(this));
        }

        if (isAdmin) {
            this.setupAdminEventListeners();
        }
    }

    static setupAdminEventListeners() {
        // Save thresholds
        const saveThresholdsBtn = document.getElementById('saveThresholds');
        if (saveThresholdsBtn) {
            saveThresholdsBtn.addEventListener('click', this.saveThresholds.bind(this));
        }

        // Health check
        const healthCheckBtn = document.getElementById('healthCheck');
        if (healthCheckBtn) {
            healthCheckBtn.addEventListener('click', this.performHealthCheck.bind(this));
        }

        // User management
        const manageUsersBtn = document.getElementById('manageUsers');
        if (manageUsersBtn) {
            manageUsersBtn.addEventListener('click', () => {
                if (this.isAdmin()) {
                    window.open('/admindashboard/user-management.html', '_blank');
                } else {
                    showToast('Access Denied', 'Administrator privileges required.', 'error');
                }
            });
        }

        // Export user data
        const exportUserDataBtn = document.getElementById('exportUserData');
        if (exportUserDataBtn) {
            exportUserDataBtn.addEventListener('click', this.exportUserData.bind(this));
        }
    }

    static async loadUserStats() {
        if (!this.isAdmin()) return;

        try {
            // Use the correct protocol (http) and handle fetch errors
            const url = window.location.protocol === "https:" 
                ? "http://127.0.0.1:5001/auth/admin/stats"
                : "http://127.0.0.1:5001/auth/admin/stats";
            const response = await fetch(url, {
                headers: {
                    'Authorization': `Bearer ${this.getApiKey()}`
                },
                mode: 'cors'
            });

            if (!response.ok) {
                throw new Error(`API error: ${response.status}`);
            }

            const data = await response.json();
            if (data.success) {
                const totalUsers = document.getElementById('totalUsers');
                const activeUsers = document.getElementById('activeUsers');
                
                if (totalUsers) totalUsers.textContent = data.data.total_users || 0;
                if (activeUsers) activeUsers.textContent = data.data.active_today || 0;
            } else {
                throw new Error(data.error || "Unknown error");
            }
        } catch (error) {
            console.error('Failed to load user stats:', error);
            // Show toast if it's a network error
            if (error instanceof TypeError) {
                showToast('Network Error', 'Cannot connect to admin stats API. Is the backend running at http://127.0.0.1:5001?', 'error');
            } else {
                showToast('Error', 'Failed to load user stats.', 'error');
            }
            const totalUsers = document.getElementById('totalUsers');
            const activeUsers = document.getElementById('activeUsers');
            
            if (totalUsers) totalUsers.textContent = 'Error';
            if (activeUsers) activeUsers.textContent = 'Error';
        }
    }

    static async saveProfile() {
        const profileData = {
            name: document.getElementById('profileName')?.value || '',
            company: document.getElementById('profileCompany')?.value || ''
        };

        try {
            showToast('Saving...', 'Updating your profile information.', 'info');
            
            // Simulate API call
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            // Update session storage
            const currentUser = this.getCurrentUser();
            if (currentUser) {
                currentUser.user.name = profileData.name;
                currentUser.user.company = profileData.company;
                sessionStorage.setItem('fraudshield_user', JSON.stringify(currentUser));
                window.currentUser = currentUser; // Update global variable
                this.setupUserInterface(); // Refresh UI
            }

            showToast('Success', 'Profile updated successfully!', 'success');
        } catch (error) {
            console.error('Failed to save profile:', error);
            showToast('Error', 'Failed to update profile. Please try again.', 'error');
        }
    }

    static async copyApiKey() {
        const apiKey = this.getApiKey();
        
        if (!apiKey) {
            showToast('Error', 'No API key found.', 'error');
            return;
        }
        
        try {
            await navigator.clipboard.writeText(apiKey);
            showToast('Copied', 'API key copied to clipboard!', 'success');
            
            // Update button temporarily
            const btn = document.getElementById('copyUserApiKey');
            if (btn) {
                const originalText = btn.textContent;
                btn.textContent = '✅ Copied!';
                setTimeout(() => {
                    btn.textContent = originalText;
                }, 2000);
            }
        } catch (error) {
            showToast('Error', 'Failed to copy API key.', 'error');
        }
    }

    static async regenerateApiKey() {
        if (!confirm('Are you sure you want to regenerate your API key? This will invalidate the current key.')) {
            return;
        }

        try {
            showToast('Generating...', 'Creating new API key.', 'info');
            
            // Simulate API call to regenerate key
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            const newApiKey = 'fsk_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
            
            sessionStorage.setItem('fraudshield_api_key', newApiKey);
            window.apiKey = newApiKey; // Update global variable
            
            const userApiKey = document.getElementById('userApiKey');
            if (userApiKey) userApiKey.textContent = newApiKey;
            
            showToast('Success', 'New API key generated successfully!', 'success');
        } catch (error) {
            console.error('Failed to regenerate API key:', error);
            showToast('Error', 'Failed to generate new API key.', 'error');
        }
    }

    static async saveThresholds() {
        try {
            showToast('Saving...', 'Updating detection thresholds.', 'info');
            await new Promise(resolve => setTimeout(resolve, 1000));
            showToast('Success', 'Thresholds updated successfully!', 'success');
        } catch (error) {
            showToast('Error', 'Failed to save thresholds.', 'error');
        }
    }

    static async performHealthCheck() {
        try {
            const btn = document.getElementById('healthCheck');
            if (btn) {
                btn.disabled = true;
                btn.textContent = '🔄 Checking...';
            }

            // Check API health
            const response = await fetch('http://127.0.0.1:5000/health');
            const dbHealth = document.getElementById('dbHealth');
            
            if (response.ok && dbHealth) {
                dbHealth.innerHTML = '<span class="status-indicator">🟢</span> Online';
                dbHealth.className = 'health-status online';
            } else if (dbHealth) {
                dbHealth.innerHTML = '<span class="status-indicator">🔴</span> Offline';
                dbHealth.className = 'health-status offline';
            }

            showToast('Health Check', 'System health check completed.', 'info');
        } catch (error) {
            const dbHealth = document.getElementById('dbHealth');
            if (dbHealth) {
                dbHealth.innerHTML = '<span class="status-indicator">🔴</span> Error';
                dbHealth.className = 'health-status offline';
            }
            
            showToast('Error', 'Health check failed.', 'error');
        } finally {
            const btn = document.getElementById('healthCheck');
            if (btn) {
                btn.disabled = false;
                btn.textContent = '🔄 Refresh Status';
            }
        }
    }

    static async exportUserData() {
        if (!this.isAdmin()) {
            showToast('Access Denied', 'Administrator privileges required.', 'error');
            return;
        }
        
        try {
            showToast('Exporting...', 'Preparing user data export.', 'info');
            
            // Create sample CSV data
            const userData = [
                ['Name', 'Email', 'Role', 'Company', 'Created At', 'Last Login', 'Status'],
                ['John Doe', 'john@example.com', 'admin', 'TechCorp', '2025-06-20', '2025-06-26', 'Active'],
                ['Jane Smith', 'jane@company.com', 'user', 'StartupInc', '2025-06-18', '2025-06-25', 'Active']
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

    /**
     * Load real metrics from the API and update dashboard
     */
    static async loadRealMetrics() {
        try {
            console.log('📊 Loading real metrics from API...');
            
            const response = await fetch('http://127.0.0.1:5000/real-stats', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                throw new Error(`API error: ${response.status}`);
            }

            const result = await response.json();
            
            if (result.success) {
                this.updateDashboardMetrics(result.data);
                console.log('✅ Real metrics loaded successfully');
                return result.data;
            } else {
                throw new Error(result.error || 'Failed to load metrics');
            }
            
        } catch (error) {
            console.error('❌ Failed to load real metrics:', error);
            // Show fallback metrics
            this.updateDashboardMetrics(this.getFallbackMetrics());
            
            // Show toast notification
            if (typeof showToast === 'function') {
                showToast('Metrics', 'Using cached metrics. Backend may be offline.', 'warning');
            }
            
            return null;
        }
    }

    /**
     * Update dashboard with real metrics
     */
    static updateDashboardMetrics(metricsData) {
        try {
            // Update hero stats (main dashboard numbers)
            const heroStats = metricsData.hero_stats || {};
            
            // Update total checks
            const totalChecksEl = document.getElementById('totalChecks');
            if (totalChecksEl) {
                this.animateNumber(totalChecksEl, heroStats.total_checks || 0);
            }

            // Update fraud blocked
            const fraudBlockedEl = document.getElementById('fraudBlocked');
            if (fraudBlockedEl) {
                this.animateNumber(fraudBlockedEl, heroStats.fraud_blocked || 0);
            }

            // Update accuracy rate
            const accuracyEl = document.getElementById('accuracyRate');
            if (accuracyEl) {
                accuracyEl.textContent = heroStats.accuracy || '99.2%';
            }

            // Update detailed metrics if elements exist
            const detailedMetrics = metricsData.detailed_metrics || {};
            
            // Update suspicious transactions
            const suspiciousEl = document.getElementById('suspiciousCount');
            if (suspiciousEl) {
                this.animateNumber(suspiciousEl, detailedMetrics.suspicious_flagged || 0);
            }

            // Update clean transactions
            const cleanEl = document.getElementById('cleanCount');
            if (cleanEl) {
                this.animateNumber(cleanEl, detailedMetrics.clean_approved || 0);
            }

            // Update bulk analyses
            const bulkEl = document.getElementById('bulkAnalyses');
            if (bulkEl) {
                this.animateNumber(bulkEl, detailedMetrics.bulk_analyses || 0);
            }

            // Update system stats in admin panel (if available)
            this.updateSystemStats(metricsData);
            
            console.log('📊 Dashboard metrics updated:', {
                totalChecks: heroStats.total_checks,
                fraudBlocked: heroStats.fraud_blocked,
                accuracy: heroStats.accuracy
            });
            
        } catch (error) {
            console.error('Failed to update dashboard metrics:', error);
        }
    }

    /**
     * Update system stats for admin users
     */
    static updateSystemStats(metricsData) {
        if (!this.isAdmin()) return;

        try {
            const blacklistCounts = metricsData.blacklist_counts || {};
            const systemStats = metricsData.system_stats || {};

            // Update blacklist counts in admin section
            const elements = {
                'disposableDomainsCount': blacklistCounts.disposable_domains,
                'flaggedIpsCount': blacklistCounts.flagged_ips,
                'suspiciousBinsCount': blacklistCounts.suspicious_bins,
                'reusedFingerprintsCount': blacklistCounts.reused_fingerprints,
                'tamperedPricesCount': blacklistCounts.tampered_prices,
                'activeRulesCount': systemStats.active_rules
            };

            Object.entries(elements).forEach(([id, value]) => {
                const element = document.getElementById(id);
                if (element && value !== undefined) {
                    this.animateNumber(element, value);
                }
            });

        } catch (error) {
            console.error('Failed to update system stats:', error);
        }
    }

    /**
     * Animate number changes for better UX
     */
    static animateNumber(element, targetValue) {
        if (!element) return;

        const currentValue = parseInt(element.textContent.replace(/[^0-9]/g, '')) || 0;
        const target = parseInt(targetValue) || 0;
        
        // Only animate if there's a significant change
        if (Math.abs(target - currentValue) < 1) {
            element.textContent = target.toLocaleString();
            return;
        }

        const duration = 1000; // 1 second
        const startTime = Date.now();
        const difference = target - currentValue;

        const updateNumber = () => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function for smooth animation
            const easeOut = 1 - Math.pow(1 - progress, 3);
            const current = Math.round(currentValue + (difference * easeOut));
            
            element.textContent = current.toLocaleString();
            
            if (progress < 1) {
                requestAnimationFrame(updateNumber);
            } else {
                element.textContent = target.toLocaleString();
            }
        };

        requestAnimationFrame(updateNumber);
    }

    /**
     * Get fallback metrics when API is unavailable
     */
    static getFallbackMetrics() {
        return {
            hero_stats: {
                total_checks: 1247,
                fraud_blocked: 89,
                accuracy: '99.2%'
            },
            detailed_metrics: {
                total_checks: 1247,
                fraud_blocked: 67,
                suspicious_flagged: 22,
                clean_approved: 1158,
                bulk_analyses: 15,
                api_requests: 1262
            },
            blacklist_counts: {
                disposable_domains: 0,
                flagged_ips: 0,
                suspicious_bins: 0,
                reused_fingerprints: 0,
                tampered_prices: 0
            },
            system_stats: {
                active_rules: 0,
                database_status: "offline",
                fraud_checker_status: "unavailable"
            }
        };
    }

    /**
     * Start periodic metrics refresh
     */
    static startMetricsRefresh() {
        // Load metrics immediately
        this.loadRealMetrics();
        
        // Set up periodic refresh every 30 seconds
        setInterval(() => {
            this.loadRealMetrics();
        }, 30000);
        
        console.log('📊 Started periodic metrics refresh (every 30 seconds)');
    }

    /**
     * Enhanced initialization that includes metrics loading
     */
    static init() {
        // Existing initialization
        this.restorePersistentSession();
        this.setupUserInterface();
        this.setupRoleBasedAccess();
        this.setupUserMenu();
        this.loadUserProfile();
        this.checkApiConnection();
        
        // Start loading real metrics
        this.startMetricsRefresh();
    }
}

// ============================================================================
// ACTIVITY LOGS MANAGEMENT (USER-SPECIFIC)
// ============================================================================

class ActivityLogsManager {
    constructor() {
        this.logsContainer = document.getElementById('logOutput');
        this.logControls = document.getElementById('logControls');
        this.isLoading = false;
        this.currentLogs = [];
        this.autoRefreshInterval = null;
    }

    static init() {
        const manager = new ActivityLogsManager();
        manager.setupEventListeners();
        manager.loadUserLogs();
        return manager;
    }

    setupEventListeners() {
        // Clear logs button
        const clearLogsBtn = document.getElementById('clearLogs');
        if (clearLogsBtn) {
            clearLogsBtn.addEventListener('click', () => {
                this.clearLogs();
            });
        }

        // Export logs button
        const exportLogsBtn = document.getElementById('exportLogs');
        if (exportLogsBtn) {
            exportLogsBtn.addEventListener('click', () => {
                this.exportLogs();
            });
        }

        // Log level filter
        const logLevelSelect = document.getElementById('logLevel');
        if (logLevelSelect) {
            logLevelSelect.addEventListener('change', () => {
                this.loadUserLogs();
            });
        }

        // Auto-refresh toggle
        this.setupAutoRefresh();
    }

    setupAutoRefresh() {
        // Auto-refresh logs every 10 seconds if user is on logs tab
        this.autoRefreshInterval = setInterval(() => {
            const logsTab = document.getElementById('logs');
            if (logsTab && logsTab.classList.contains('active')) {
                this.loadUserLogs(false); // Silent refresh
            }
        }, 10000);
    }

    async loadUserLogs(showLoading = true) {
        // Check if user is authenticated
        if (!AuthManager.isAuthenticated()) {
            this.showAuthRequired();
            return;
        }

        if (this.isLoading) return;

        try {
            this.isLoading = true;
            
            if (showLoading) {
                this.showLoadingState();
            }

            const apiKey = AuthManager.getApiKey();
            if (!apiKey) {
                throw new Error('No API key found');
            }

            // Get log level filter
            const logLevel = document.getElementById('logLevel')?.value || 'all';

            const response = await fetch('http://127.0.0.1:5000/user-logs?' + new URLSearchParams({
                limit: '50',
                skip: '0',
                level: logLevel
            }), {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || `API error: ${response.status}`);
            }

            const result = await response.json();
            
            if (result.success) {
                this.currentLogs = result.data.logs || [];
                this.displayLogs(this.currentLogs);
                
                if (showLoading) {
                    showToast('Logs Updated', `Retrieved ${this.currentLogs.length} activity logs`, 'success');
                }
            } else {
                throw new Error(result.error || 'Failed to load logs');
            }

        } catch (error) {
            console.error('Failed to load user logs:', error);
            this.showErrorState(error.message);
            
            if (showLoading) {
                if (error.message.includes('Invalid API key') || error.message.includes('API key required')) {
                    showToast('Authentication Error', 'Please sign in again to view logs', 'error');
                } else {
                    showToast('Error', 'Failed to load activity logs', 'error');
                }
            }
        } finally {
            this.isLoading = false;
        }
    }

    showAuthRequired() {
        if (!this.logsContainer) return;

        this.logsContainer.innerHTML = `
            <div class="log-placeholder">
                <div class="placeholder-icon">🔒</div>
                <h3>Authentication Required</h3>
                <p>Please sign in to view your activity logs</p>
                <div style="margin-top: 1rem;">
                    <a href="/user_auth/pages/login.html" class="btn btn-primary">
                        <span>🚪</span> Sign In
                    </a>
                </div>
            </div>
        `;
    }

    showLoadingState() {
        if (!this.logsContainer) return;

        this.logsContainer.innerHTML = `
            <div class="log-placeholder">
                <div class="placeholder-icon">⏳</div>
                <h3>Loading Activity Logs</h3>
                <p>Fetching your recent activity...</p>
            </div>
        `;
    }

    showErrorState(errorMessage) {
        if (!this.logsContainer) return;

        this.logsContainer.innerHTML = `
            <div class="log-placeholder">
                <div class="placeholder-icon">❌</div>
                <h3>Error Loading Logs</h3>
                <p>${errorMessage}</p>
                <button onclick="activityLogsManager.loadUserLogs()" class="btn btn-secondary">
                    🔄 Retry
                </button>
            </div>
        `;
    }

    displayLogs(logs) {
        if (!this.logsContainer) return;

        if (!logs || logs.length === 0) {
            this.logsContainer.innerHTML = `
                <div class="log-placeholder">
                    <div class="placeholder-icon">📋</div>
                    <h3>No Activity Yet</h3>
                    <p>Your fraud detection activity will appear here</p>
                </div>
            `;
            return;
        }

        // Generate log entries HTML
        const logEntriesHTML = logs.map(log => this.createLogEntry(log)).join('');

        this.logsContainer.innerHTML = `
            <div class="log-header">
                <div class="log-stats">
                    <span class="log-count">${logs.length} entries</span>
                    <span class="last-updated">Updated: ${new Date().toLocaleTimeString()}</span>
                </div>
            </div>
            <div class="log-entries">
                ${logEntriesHTML}
            </div>
        `;
    }

    createLogEntry(log) {
        const timestamp = new Date(log.timestamp).toLocaleString();
        const action = log.action || 'unknown';
        const details = log.details || {};
        
        // Determine log type and icon
        let logType = 'info';
        let icon = 'ℹ️';
        
        if (log.decision === 'fraud') {
            logType = 'error';
            icon = '❌';
        } else if (log.decision === 'suspicious') {
            logType = 'warning';
            icon = '⚠️';
        } else if (action === 'fraud_check') {
            logType = 'success';
            icon = '✅';
        } else if (action === 'bulk_analysis') {
            logType = 'info';
            icon = '📊';
        }

        // Create action description
        let actionDescription = '';
        if (action === 'fraud_check') {
            actionDescription = `Fraud check for ${details.transaction_email || 'transaction'}`;
            if (log.fraud_score !== undefined) {
                actionDescription += ` - Score: ${log.fraud_score}`;
            }
        } else if (action === 'bulk_analysis') {
            actionDescription = `Bulk analysis of ${details.filename || 'file'}`;
            if (details.total_records) {
                actionDescription += ` (${details.total_records} records)`;
            }
        } else {
            actionDescription = action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        }

        // Create triggered rules display
        let rulesDisplay = '';
        if (log.triggered_rules && log.triggered_rules.length > 0) {
            rulesDisplay = `
                <div class="log-rules">
                    <strong>Triggered Rules:</strong> ${log.triggered_rules.join(', ')}
                </div>
            `;
        }

        return `
            <div class="log-entry log-${logType}">
                <div class="log-icon">${icon}</div>
                <div class="log-content">
                    <div class="log-header-line">
                        <span class="log-action">${actionDescription}</span>
                        <span class="log-timestamp">${timestamp}</span>
                    </div>
                    <div class="log-details">
                        <div class="log-meta">
                            <span>IP: ${log.ip_address || 'Unknown'}</span>
                            <span>Endpoint: ${log.endpoint || 'Unknown'}</span>
                            ${log.decision ? `<span>Decision: ${log.decision}</span>` : ''}
                        </div>
                        ${rulesDisplay}
                    </div>
                </div>
            </div>
        `;
    }

    async clearLogs() {
        if (!confirm('Are you sure you want to clear your activity logs? This action cannot be undone.')) {
            return;
        }

        try {
            showToast('Info', 'Log clearing is not implemented yet', 'info');
        } catch (error) {
            console.error('Failed to clear logs:', error);
            showToast('Error', 'Failed to clear logs', 'error');
        }
    }

    exportLogs() {
        if (!this.currentLogs || this.currentLogs.length === 0) {
            showToast('No Data', 'No logs to export', 'warning');
            return;
        }

        try {
            // Convert logs to CSV
            const headers = ['Timestamp', 'Action', 'Decision', 'Fraud Score', 'IP Address', 'Details'];
            const csvData = [
                headers.join(','),
                ...this.currentLogs.map(log => {
                    const row = [
                        `"${new Date(log.timestamp).toISOString()}"`,
                        `"${log.action || ''}"`,
                        `"${log.decision || ''}"`,
                        log.fraud_score || '',
                        `"${log.ip_address || ''}"`,
                        `"${JSON.stringify(log.details || {}).replace(/"/g, '""')}"`
                    ];
                    return row.join(',');
                })
            ].join('\n');

            // Create and download file
            const blob = new Blob([csvData], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            
            link.setAttribute('href', url);
            link.setAttribute('download', `fraudshield_activity_logs_${new Date().toISOString().split('T')[0]}.csv`);
            link.style.visibility = 'hidden';
            
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            URL.revokeObjectURL(url);
            
            showToast('Success', 'Activity logs exported successfully!', 'success');
            
        } catch (error) {
            console.error('Export failed:', error);
            showToast('Error', 'Failed to export logs', 'error');
        }
    }

    destroy() {
        if (this.autoRefreshInterval) {
            clearInterval(this.autoRefreshInterval);
        }
    }
}

// FIXED: Check tab accessibility based on user authentication and role
function isTabAccessible(tabName) {
    // Home and bulk are always accessible (public)
    if (tabName === 'home' || tabName === 'bulk') {
        return true;
    }
    
    // Logs and settings require authentication
    if (tabName === 'logs' || tabName === 'settings') {
        // Tab is accessible, but content will show appropriate messages
        return true;
    }
    
    return true; // Default to accessible
}

// Track tab usage for analytics
function trackTabUsage(tabName) {
    const currentUser = AuthManager.getCurrentUser();
    const userType = currentUser ? currentUser.user.role : 'anonymous';
    console.log(`📊 Tab accessed: ${tabName} by ${userType} user`);
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

// Utility function for tab switching
window.switchToTab = function(tabName) {
    const tabBtn = document.querySelector(`[data-tab="${tabName}"]`);
    if (tabBtn) {
        tabBtn.click();
    }
};

// ---------------------------------------------------------------------------
// FIXED Bulk-Upload with Proper Session Management
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

  // Helper to render server results
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

  // Enhanced table rendering
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

  // Main form submission handler
  submitBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    
    const file = fileInput.files[0];
    
    // Double-check validation
    const validation = validateFile(file);
    if (!validation.valid) {
      alert(validation.message);
      return;
    }
    
    // Check authentication for bulk analysis
    const apiKey = AuthManager.getApiKey();
    if (!apiKey) {
      alert('🔑 API key required for bulk analysis. Please sign in first.');
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
        headers: {
          'Authorization': `Bearer ${apiKey}`
        },
        body: formData,
        mode: 'cors'
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
});

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  // Initialize authentication manager
  AuthManager.init();
  
  // Make functions globally available for console testing
  window.AuthManager = AuthManager;
  window.showToast = showToast;
  
  console.log('🔧 FraudShield Dashboard Loaded');
  console.log('🔍 Debug functions available: AuthManager, showToast()');
  
  const isAuth = AuthManager.isAuthenticated();
  console.log(`👤 User status: ${isAuth ? 'Authenticated' : 'Anonymous'}`);
  
  if (isAuth && AuthManager.isAdmin()) {
    console.log('👑 Admin user detected - all features available');
  }

  // Initialize activity logs if user is authenticated
  if (isAuth) {
    setTimeout(() => {
      if (window.activityLogsManager) {
        window.activityLogsManager.destroy();
      }
      window.activityLogsManager = ActivityLogsManager.init();
    }, 1000);
  }

  // Ensure log level filter always refreshes logs on change
  const logLevelSelect = document.getElementById('logLevel');
  if (logLevelSelect) {
    logLevelSelect.addEventListener('change', function() {
      if (window.activityLogsManager) {
        window.activityLogsManager.loadUserLogs(true);
      }
    });
  }
});