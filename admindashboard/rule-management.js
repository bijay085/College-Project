// Rule Management System - Updated for Optimized Database Structure
class RuleManager {
    constructor() {
        this.rules = [];
        this.originalRules = {};
        this.modifiedRules = new Set();
        this.apiUrl = 'http://127.0.0.1:5000';
        this.authApiUrl = 'http://127.0.0.1:5001/auth';
        this.init();
    }

    async init() {
        // Check authentication
        if (!this.checkAuth()) {
            window.location.href = '../user_auth/pages/login.html';
            return;
        }

        // Setup event listeners
        this.setupEventListeners();
        
        // Load rules and system health
        await this.loadRules();
        await this.checkSystemHealth();
    }

    checkAuth() {
        const userData = sessionStorage.getItem('fraudshield_user');
        const apiKey = sessionStorage.getItem('fraudshield_api_key');
        
        if (!userData || !apiKey) {
            // Check persistent storage
            const persistentUser = localStorage.getItem('fraudshield_persistent_user');
            const persistentKey = localStorage.getItem('fraudshield_persistent_api_key');
            
            if (persistentUser && persistentKey) {
                sessionStorage.setItem('fraudshield_user', persistentUser);
                sessionStorage.setItem('fraudshield_api_key', persistentKey);
                return this.checkAuth();
            }
            return false;
        }

        try {
            const user = JSON.parse(userData);
            if (user.user.role !== 'admin') {
                this.showToast('Access denied. Admin privileges required.', 'error');
                return false;
            }
            
            document.getElementById('adminName').textContent = user.user.name || 'Admin';
            return true;
        } catch (e) {
            return false;
        }
    }

    setupEventListeners() {
        document.getElementById('refreshBtn').addEventListener('click', () => this.loadRules());
        document.getElementById('saveAllBtn').addEventListener('click', () => this.saveAllChanges());
        document.getElementById('logoutBtn').addEventListener('click', () => this.logout());
        
        // Session monitoring
        window.addEventListener('storage', (e) => {
            if (e.key === 'fraudshield_user' || e.key === 'fraudshield_api_key') {
                if (!e.newValue) {
                    window.location.href = '../user_auth/pages/login.html';
                }
            }
        });
        
        // Periodic auth check
        setInterval(() => {
            if (!this.checkAuth()) {
                window.location.href = '../user_auth/pages/login.html';
            }
        }, 60000); // Check every minute
    }

    async loadRules() {
        const container = document.getElementById('rulesContainer');
        container.innerHTML = '<div class="loading-spinner">Loading rules...</div>';

        try {
            const apiKey = sessionStorage.getItem('fraudshield_api_key');
            const response = await fetch(`${this.apiUrl}/admin/rules`, {
                headers: {
                    'Authorization': `Bearer ${apiKey}`
                }
            });

            if (!response.ok) {
                throw new Error('Failed to load rules');
            }

            const data = await response.json();
            this.rules = data.rules || [];
            this.originalRules = {};
            this.modifiedRules.clear();
            
            // Store original values
            this.rules.forEach(rule => {
                this.originalRules[rule._id] = {
                    enabled: rule.enabled,
                    weight: rule.weight
                };
            });

            this.renderRules();
            this.updateStats();
            this.disableSaveButton();
            
        } catch (error) {
            console.error('Failed to load rules:', error);
            this.showToast('Failed to load rules', 'error');
            container.innerHTML = '<div class="error-message">Failed to load rules. Please try again.</div>';
        }
    }

    renderRules() {
        const container = document.getElementById('rulesContainer');
        const categories = this.groupRulesByCategory();
        
        container.innerHTML = '';

        Object.entries(categories).forEach(([category, rules]) => {
            const section = this.createCategorySection(category, rules);
            container.appendChild(section);
        });
    }

    groupRulesByCategory() {
        const categories = {};
        
        this.rules.forEach(rule => {
            const category = rule.category || 'uncategorized';
            if (!categories[category]) {
                categories[category] = [];
            }
            categories[category].push(rule);
        });

        // Sort categories by priority
        const sortedCategories = {};
        ['critical', 'behavioral', 'medium', 'low', 'experimental'].forEach(cat => {
            if (categories[cat]) {
                sortedCategories[cat] = categories[cat];
            }
        });

        // Add any remaining categories
        Object.keys(categories).forEach(cat => {
            if (!sortedCategories[cat]) {
                sortedCategories[cat] = categories[cat];
            }
        });

        return sortedCategories;
    }

    createCategorySection(category, rules) {
        const section = document.createElement('div');
        section.className = 'category-section';

        const categoryIcons = {
            'critical': '🚨',
            'behavioral': '🧠',
            'medium': '⚠️',
            'low': 'ℹ️',
            'experimental': '🔬'
        };

        const categoryNames = {
            'critical': 'Critical Rules',
            'behavioral': 'Behavioral Analysis',
            'medium': 'Medium Priority',
            'low': 'Low Priority',
            'experimental': 'Experimental (Disabled)'
        };

        section.innerHTML = `
            <div class="category-header">
                <span class="category-icon">${categoryIcons[category] || '📋'}</span>
                <h3 class="category-title">${categoryNames[category] || category}</h3>
                <span class="category-count">${rules.length} rules</span>
            </div>
        `;

        const rulesContainer = document.createElement('div');
        rulesContainer.className = 'category-rules';

        rules.forEach(rule => {
            const ruleElement = this.createRuleElement(rule);
            rulesContainer.appendChild(ruleElement);
        });

        section.appendChild(rulesContainer);
        return section;
    }

    createRuleElement(rule) {
        const ruleDiv = document.createElement('div');
        ruleDiv.className = 'rule-item';
        ruleDiv.id = `rule-${rule._id}`;

        ruleDiv.innerHTML = `
            <label class="rule-toggle">
                <input type="checkbox" ${rule.enabled ? 'checked' : ''} 
                       onchange="ruleManager.toggleRule('${rule._id}')">
                <span class="toggle-slider"></span>
            </label>
            
            <div class="rule-key">${rule.rule_key}</div>
            
            <div class="rule-description">${rule.description || 'No description'}</div>
            
            <div class="rule-weight-control">
                <input type="number" 
                       class="weight-input" 
                       value="${rule.weight}" 
                       min="0" 
                       max="1" 
                       step="0.05"
                       onchange="ruleManager.updateWeight('${rule._id}', this.value)">
            </div>
            
            <div class="rule-status">
                <span class="${rule.enabled ? 'status-enabled' : 'status-disabled'}">
                    ${rule.enabled ? 'Enabled' : 'Disabled'}
                </span>
            </div>
            
            <div class="rule-actions">
                <button class="btn btn-save-rule" onclick="ruleManager.saveRule('${rule._id}')" style="display: none;">
                    Save
                </button>
                <button class="btn btn-reset-rule" onclick="ruleManager.resetRule('${rule._id}')" style="display: none;">
                    Reset
                </button>
            </div>
        `;

        return ruleDiv;
    }

    toggleRule(ruleId) {
        const rule = this.rules.find(r => r._id === ruleId);
        if (rule) {
            rule.enabled = !rule.enabled;
            this.markAsModified(ruleId);
            this.updateRuleUI(ruleId);
        }
    }

    updateWeight(ruleId, newWeight) {
        const rule = this.rules.find(r => r._id === ruleId);
        if (rule) {
            rule.weight = parseFloat(newWeight) || 0;
            this.markAsModified(ruleId);
            this.updateRuleUI(ruleId);
        }
    }

    markAsModified(ruleId) {
        const rule = this.rules.find(r => r._id === ruleId);
        const original = this.originalRules[ruleId];
        
        if (rule && original) {
            if (rule.enabled !== original.enabled || rule.weight !== original.weight) {
                this.modifiedRules.add(ruleId);
            } else {
                this.modifiedRules.delete(ruleId);
            }
        }

        this.updateSaveButton();
        this.updateRuleUI(ruleId);
    }

    updateRuleUI(ruleId) {
        const ruleElement = document.getElementById(`rule-${ruleId}`);
        const rule = this.rules.find(r => r._id === ruleId);
        
        if (ruleElement && rule) {
            // Update modified state
            if (this.modifiedRules.has(ruleId)) {
                ruleElement.classList.add('modified');
                ruleElement.querySelector('.btn-save-rule').style.display = 'inline-flex';
                ruleElement.querySelector('.btn-reset-rule').style.display = 'inline-flex';
            } else {
                ruleElement.classList.remove('modified');
                ruleElement.querySelector('.btn-save-rule').style.display = 'none';
                ruleElement.querySelector('.btn-reset-rule').style.display = 'none';
            }

            // Update status
            const statusElement = ruleElement.querySelector('.rule-status span');
            statusElement.className = rule.enabled ? 'status-enabled' : 'status-disabled';
            statusElement.textContent = rule.enabled ? 'Enabled' : 'Disabled';
        }
    }

    async saveRule(ruleId) {
        const rule = this.rules.find(r => r._id === ruleId);
        if (!rule) return;

        try {
            const apiKey = sessionStorage.getItem('fraudshield_api_key');
            const response = await fetch(`${this.apiUrl}/admin/rules/${ruleId}`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    enabled: rule.enabled,
                    weight: rule.weight
                })
            });

            if (!response.ok) {
                throw new Error('Failed to save rule');
            }

            // Update original values
            this.originalRules[ruleId] = {
                enabled: rule.enabled,
                weight: rule.weight
            };
            
            this.modifiedRules.delete(ruleId);
            this.updateRuleUI(ruleId);
            this.updateSaveButton();
            this.showToast(`Rule "${rule.rule_key}" saved successfully`, 'success');
            
        } catch (error) {
            console.error('Failed to save rule:', error);
            this.showToast('Failed to save rule', 'error');
        }
    }

    resetRule(ruleId) {
        const rule = this.rules.find(r => r._id === ruleId);
        const original = this.originalRules[ruleId];
        
        if (rule && original) {
            rule.enabled = original.enabled;
            rule.weight = original.weight;
            
            // Update UI
            const ruleElement = document.getElementById(`rule-${ruleId}`);
            if (ruleElement) {
                const checkbox = ruleElement.querySelector('input[type="checkbox"]');
                const weightInput = ruleElement.querySelector('.weight-input');
                
                checkbox.checked = rule.enabled;
                weightInput.value = rule.weight;
            }
            
            this.markAsModified(ruleId);
        }
    }

    async saveAllChanges() {
        if (this.modifiedRules.size === 0) return;

        const saveButton = document.getElementById('saveAllBtn');
        saveButton.disabled = true;
        saveButton.innerHTML = '<span class="loading-spinner"></span> Saving...';

        try {
            const updates = [];
            
            this.modifiedRules.forEach(ruleId => {
                const rule = this.rules.find(r => r._id === ruleId);
                if (rule) {
                    updates.push({
                        _id: rule._id,
                        enabled: rule.enabled,
                        weight: rule.weight
                    });
                }
            });

            const apiKey = sessionStorage.getItem('fraudshield_api_key');
            const response = await fetch(`${this.apiUrl}/admin/rules/batch`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ updates })
            });

            if (!response.ok) {
                throw new Error('Failed to save changes');
            }

            // Update original values
            this.modifiedRules.forEach(ruleId => {
                const rule = this.rules.find(r => r._id === ruleId);
                if (rule) {
                    this.originalRules[ruleId] = {
                        enabled: rule.enabled,
                        weight: rule.weight
                    };
                }
            });

            this.modifiedRules.clear();
            this.renderRules();
            this.showToast(`${updates.length} rules updated successfully`, 'success');
            
        } catch (error) {
            console.error('Failed to save changes:', error);
            this.showToast('Failed to save changes', 'error');
        } finally {
            saveButton.disabled = false;
            saveButton.innerHTML = '<span class="icon">💾</span> Save Changes';
            this.updateSaveButton();
        }
    }

    updateSaveButton() {
        const saveButton = document.getElementById('saveAllBtn');
        saveButton.disabled = this.modifiedRules.size === 0;
        
        if (this.modifiedRules.size > 0) {
            saveButton.innerHTML = `<span class="icon">💾</span> Save Changes (${this.modifiedRules.size})`;
        } else {
            saveButton.innerHTML = '<span class="icon">💾</span> Save Changes';
        }
    }

    disableSaveButton() {
        document.getElementById('saveAllBtn').disabled = true;
    }

    updateStats() {
        const stats = {
            total: this.rules.length,
            enabled: this.rules.filter(r => r.enabled).length,
            critical: this.rules.filter(r => r.category === 'critical').length,
            behavioral: this.rules.filter(r => r.category === 'behavioral').length
        };

        document.getElementById('totalRules').textContent = stats.total;
        document.getElementById('enabledRules').textContent = stats.enabled;
        document.getElementById('basicRules').textContent = stats.critical;
        document.getElementById('advancedRules').textContent = stats.behavioral;
    }

    async checkSystemHealth() {
        try {
            const apiKey = sessionStorage.getItem('fraudshield_api_key');
            
            // Check fraud API health
            const fraudHealthResponse = await fetch(`${this.apiUrl}/health`);
            const fraudHealth = await fraudHealthResponse.json();
            
            // Check auth API health
            const authHealthResponse = await fetch(`${this.authApiUrl}/health`, {
                headers: {
                    'Authorization': `Bearer ${apiKey}`
                }
            });
            const authHealth = await authHealthResponse.json();
            
            // Update UI based on health status
            if (fraudHealth.status === 'online' && authHealth.status === 'healthy') {
                console.log('✅ All systems operational');
            } else {
                console.warn('⚠️ System health degraded', { fraudHealth, authHealth });
            }
            
        } catch (error) {
            console.error('Failed to check system health:', error);
        }
    }

    showToast(message, type = 'info') {
        const toast = document.getElementById('toast');
        toast.className = `toast ${type} show`;
        toast.textContent = message;

        setTimeout(() => {
            toast.classList.remove('show');
        }, 3000);
    }

    logout() {
        // Clear session
        sessionStorage.clear();
        localStorage.removeItem('fraudshield_persistent_user');
        localStorage.removeItem('fraudshield_persistent_api_key');
        localStorage.removeItem('fraudshield_persistent_session_id');
        localStorage.removeItem('fraudshield_remember');
        localStorage.removeItem('fraudshield_email');
        
        window.location.href = '../user_auth/pages/login.html';
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.ruleManager = new RuleManager();
});