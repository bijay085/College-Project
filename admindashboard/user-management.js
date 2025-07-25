class ApiService {
    constructor(baseUrl, headers) {
        this.baseUrl = baseUrl;
        this.headers = headers;
    }

    async request(endpoint, options = {}) {
        const response = await fetch(`${this.baseUrl}${endpoint}`, {
            ...options,
            headers: { ...this.headers(), ...options.headers }
        });
        
        if (!response.ok) {
            const error = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
            throw new Error(error.error || error.message || `HTTP ${response.status}`);
        }
        
        return response.json();
    }

    get(endpoint, params) {
        const url = params ? `${endpoint}?${new URLSearchParams(params)}` : endpoint;
        return this.request(url);
    }

    post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }
}

class AuthManager {
    static keys = {
        user: 'fraudshield_user',
        apiKey: 'fraudshield_api_key',
        persistentUser: 'fraudshield_persistent_user',
        persistentKey: 'fraudshield_persistent_api_key'
    };

    static getAuth() {
        let user = sessionStorage.getItem(this.keys.user);
        let apiKey = sessionStorage.getItem(this.keys.apiKey);
        
        if (!user || !apiKey) {
            user = localStorage.getItem(this.keys.persistentUser);
            apiKey = localStorage.getItem(this.keys.persistentKey);
            
            if (user && apiKey) {
                sessionStorage.setItem(this.keys.user, user);
                sessionStorage.setItem(this.keys.apiKey, apiKey);
            }
        }
        
        return { user: user ? JSON.parse(user) : null, apiKey };
    }

    static requireAdmin() {
        const { user, apiKey } = this.getAuth();
        
        if (!user || !apiKey) {
            window.location.href = `/user_auth/pages/login.html?redirect=${encodeURIComponent(window.location.pathname)}`;
            return null;
        }
        
        if (user.user.role !== 'admin') {
            alert('Admin access required');
            window.location.href = '/index.html';
            return null;
        }
        
        return { user: user.user, apiKey };
    }
}

class UIRenderer {
    static escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    static formatDate(dateString) {
        if (!dateString) return 'Never';
        
        const date = new Date(dateString);
        const now = new Date();
        const diffTime = Math.abs(now - date);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        
        if (diffDays === 0) return 'Today';
        if (diffDays === 1) return 'Yesterday';
        if (diffDays <= 7) return `${diffDays} days ago`;
        
        return date.toLocaleDateString();
    }

    static getUserStatus(user) {
        if (user.locked_until && new Date(user.locked_until) > new Date()) return 'locked';
        if (!user.last_login) return 'pending';
        
        const lastLogin = new Date(user.last_login);
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        
        return lastLogin < thirtyDaysAgo ? 'inactive' : 'active';
    }

    static getStatusText(status) {
        const statusMap = { active: 'Active', inactive: 'Inactive', pending: 'Pending', locked: 'Locked' };
        return statusMap[status] || status.charAt(0).toUpperCase() + status.slice(1);
    }

    static userRow(user, management) {
        const status = this.getUserStatus(user);
        
        return `
            <tr data-user-id="${user.id}">
                <td>
                    <div class="user-info">
                        <div class="user-avatar">${user.name.charAt(0).toUpperCase()}</div>
                        <div class="user-details">
                            <h4>${this.escapeHtml(user.name)}</h4>
                            <p>ID: ${user.id}</p>
                        </div>
                    </div>
                </td>
                <td>${this.escapeHtml(user.email)}</td>
                <td><span class="role-badge role-${user.role}">${user.role === 'admin' ? 'Administrator' : 'User'}</span></td>
                <td>${this.escapeHtml(user.company || '-')}</td>
                <td>${this.formatDate(user.last_login)}</td>
                <td><span class="status-badge status-${status}"><i class="fas fa-circle"></i> ${this.getStatusText(status)}</span></td>
                <td>
                    <div class="action-buttons">
                        <button class="btn-icon btn-edit" data-user-id="${user.id}" title="Edit User"><i class="fas fa-edit"></i></button>
                        <button class="btn-icon btn-view" data-user-id="${user.id}" title="View Details"><i class="fas fa-eye"></i></button>
                        <button class="btn-icon danger btn-delete" data-user-id="${user.id}" title="Delete User"><i class="fas fa-trash"></i></button>
                    </div>
                </td>
            </tr>
        `;
    }

    static userDetailsModal(user, management) {
        const status = this.getUserStatus(user);
        
        return `
            <div class="modal-overlay" id="detailsModal">
                <div class="modal user-details-modal">
                    <div class="modal-header">
                        <div class="user-header-info">
                            <div class="user-avatar-large">${user.name.charAt(0).toUpperCase()}</div>
                            <div class="user-title-info">
                                <h2>${this.escapeHtml(user.name)}</h2>
                                <p class="user-email">${this.escapeHtml(user.email)}</p>
                                <span class="role-badge role-${user.role}">${user.role === 'admin' ? 'Administrator' : 'User'}</span>
                            </div>
                        </div>
                        <button class="close-btn" onclick="userManagement.closeDetailsModal()"><i class="fas fa-times"></i></button>
                    </div>
                    
                    <div class="modal-body">
                        <div class="details-grid">
                            <div class="detail-section">
                                <h3><i class="fas fa-user"></i> Account Information</h3>
                                ${this.detailRow('User ID', user.id)}
                                ${this.detailRow('Company', this.escapeHtml(user.company || 'Not specified'))}
                                ${this.detailRow('Created', user.created_at ? new Date(user.created_at).toLocaleDateString() : 'Unknown')}
                                ${this.detailRow('Last Login', this.formatDate(user.last_login))}
                                ${this.detailRow('Status', `<span class="status-badge status-${status}">${this.getStatusText(status)}</span>`)}
                            </div>
                            
                            <div class="detail-section">
                                <h3><i class="fas fa-shield-alt"></i> Security Information</h3>
                                ${this.detailRow('Email Verified', `<span class="${user.is_verified ? 'text-success' : ''}">${user.is_verified ? 'Yes' : 'No'}</span>`)}
                                ${this.detailRow('Login Attempts', user.login_attempts || 0)}
                                ${this.detailRow('Security Score', user.security_score ? `${(user.security_score * 100).toFixed(0)}%` : 'N/A')}
                                ${this.detailRow('Last IP', `<span class="mono">${user.last_ip || 'Unknown'}</span>`)}
                            </div>
                            
                            <div class="detail-section full-width">
                                <h3><i class="fas fa-key"></i> API Access</h3>
                                <div class="api-key-container">
                                    <label class="detail-label">API Key</label>
                                    <div class="api-key-display">${user.api_key ? user.api_key.substring(0, 20) + '...' : 'No API key'}</div>
                                    ${user.api_key ? `<button class="copy-api-btn" onclick="userManagement.copyUserApiKey('${user.api_key}')">Copy</button>` : ''}
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="modal-footer">
                        <button class="btn btn-secondary" onclick="userManagement.closeDetailsModal()"><i class="fas fa-times"></i> Close</button>
                        <button class="btn btn-primary" onclick="userManagement.editUser('${user.id}'); userManagement.closeDetailsModal();"><i class="fas fa-edit"></i> Edit User</button>
                    </div>
                </div>
            </div>
        `;
    }

    static detailRow(label, value) {
        return `<div class="detail-row"><span class="detail-label">${label}</span><span class="detail-value">${value}</span></div>`;
    }
}

class ToastManager {
    static show(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icons = { success: 'check-circle', error: 'exclamation-circle', info: 'info-circle' };
        toast.innerHTML = `
            <div style="display: flex; align-items: center; gap: 0.5rem;">
                <i class="fas fa-${icons[type] || icons.info}"></i>
                <span>${UIRenderer.escapeHtml(message)}</span>
            </div>
        `;
        
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 5000);
    }
}

class UserManagement {
    constructor() {
        this.API_BASE_URL = 'http://127.0.0.1:5001/auth';
        this.FRAUD_API_URL = 'http://127.0.0.1:5000';
        this.users = [];
        this.filteredUsers = [];
        this.currentUser = null;
        this.currentEditUserId = null;
        this.pagination = { page: 1, limit: 50, total: 0, pages: 0 };
        
        this.init();
    }

    init() {
        const auth = AuthManager.requireAdmin();
        if (!auth) return;
        
        this.currentApiKey = auth.apiKey;
        this.currentUser = auth.user;
        
        this.api = new ApiService(this.API_BASE_URL, () => ({
            'Authorization': `Bearer ${this.currentApiKey}`,
            'Content-Type': 'application/json'
        }));
        
        this.setupEventListeners();
        this.loadUsers();
        this.loadStats();
        this.startPeriodicRefresh();
    }

    setupEventListeners() {
        const els = {
            searchInput: document.getElementById('searchInput'),
            roleFilter: document.getElementById('roleFilter'),
            refreshBtn: document.getElementById('refreshBtn'),
            createUserBtn: document.getElementById('createUserBtn'),
            closeModalBtn: document.getElementById('closeModalBtn'),
            userModal: document.getElementById('userModal'),
            userForm: document.getElementById('userForm'),
            deleteUserBtn: document.getElementById('deleteUserBtn'),
            cancelBtn: document.getElementById('cancelBtn'),
            regenerateApiBtn: document.getElementById('regenerateApiBtn'),
            copyApiBtn: document.getElementById('copyApiBtn'),
            usersTableBody: document.getElementById('usersTableBody')
        };

        els.searchInput?.addEventListener('input', () => this.filterUsers());
        els.roleFilter?.addEventListener('change', () => this.filterUsers());
        els.refreshBtn?.addEventListener('click', () => { this.loadUsers(); this.loadStats(); });
        els.createUserBtn?.addEventListener('click', () => this.openUserModal());
        els.closeModalBtn?.addEventListener('click', () => this.closeModal());
        els.userModal?.addEventListener('click', (e) => { if (e.target.id === 'userModal') this.closeModal(); });
        els.userForm?.addEventListener('submit', (e) => { e.preventDefault(); this.saveUser(); });
        els.deleteUserBtn?.addEventListener('click', () => this.deleteUser());
        els.cancelBtn?.addEventListener('click', () => this.closeModal());
        els.regenerateApiBtn?.addEventListener('click', () => this.regenerateApiKey());
        els.copyApiBtn?.addEventListener('click', () => this.copyApiKey());

        // Event delegation for table action buttons
        els.usersTableBody?.addEventListener('click', (e) => {
            const btn = e.target.closest('button');
            if (!btn) return;

            const userId = btn.dataset.userId;
            if (!userId) return;

            if (btn.classList.contains('btn-edit')) {
                this.editUser(userId);
            } else if (btn.classList.contains('btn-view')) {
                this.viewUserDetails(userId);
            } else if (btn.classList.contains('btn-delete')) {
                this.confirmDeleteUser(userId);
            }
        });

        window.addEventListener('storage', (e) => {
            if ((e.key === AuthManager.keys.user || e.key === AuthManager.keys.apiKey) && !e.newValue) {
                window.location.href = '/user_auth/pages/login.html';
            }
        });
    }

    async loadUsers() {
        try {
            this.showLoading(true);
            
            const params = {
                page: this.pagination.page.toString(),
                limit: this.pagination.limit.toString()
            };
            
            const searchTerm = document.getElementById('searchInput').value.trim();
            const roleFilter = document.getElementById('roleFilter').value;
            
            if (searchTerm) params.search = searchTerm;
            if (roleFilter) params.role = roleFilter;
            
            const result = await this.api.get('/users', params);
            
            if (result.success) {
                this.users = result.data.users || [];
                this.pagination = result.data.pagination || this.pagination;
                this.filteredUsers = [...this.users];
                this.renderUsers();
            } else {
                throw new Error(result.error || 'Failed to load users');
            }
        } catch (error) {
            ToastManager.show(`Failed to load users: ${error.message}`, 'error');
            this.users = [];
            this.filteredUsers = [];
            this.renderUsers();
        } finally {
            this.showLoading(false);
        }
    }

    async loadStats() {
        try {
            const result = await this.api.get('/admin/stats');
            
            if (result.success) {
                const stats = result.data;
                document.getElementById('totalUsers').textContent = stats.total_users || 0;
                document.getElementById('activeUsers').textContent = stats.active_today || 0;
                document.getElementById('adminUsers').textContent = stats.admin_users || 0;
                document.getElementById('newUsers').textContent = stats.new_this_week || 0;
                
                console.log('📊 Stats loaded:', {
                    total_users: stats.total_users,
                    active_today: stats.active_today,
                    admin_users: stats.admin_users,
                    new_this_week: stats.new_this_week,
                    raw_response: stats
                });
            } else {
                throw new Error(result.error || 'Failed to load stats');
            }
        } catch (error) {
            console.error('❌ Stats loading error:', error);
            
            // Calculate stats from loaded users as fallback
            const now = new Date();
            const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            const weekAgo = new Date(today);
            weekAgo.setDate(weekAgo.getDate() - 7);
            
            const activeToday = this.users.filter(u => {
                if (!u.last_login) return false;
                const lastLogin = new Date(u.last_login);
                return lastLogin >= today;
            }).length;
            
            const newThisWeek = this.users.filter(u => {
                if (!u.created_at) return false;
                const created = new Date(u.created_at);
                return created >= weekAgo;
            }).length;
            
            document.getElementById('totalUsers').textContent = this.users.length;
            document.getElementById('activeUsers').textContent = activeToday;
            document.getElementById('adminUsers').textContent = this.users.filter(u => u.role === 'admin').length;
            document.getElementById('newUsers').textContent = newThisWeek;
            
            console.log('📊 Calculated stats from users:', {
                total: this.users.length,
                activeToday,
                adminCount: this.users.filter(u => u.role === 'admin').length,
                newThisWeek,
                today: today.toISOString(),
                weekAgo: weekAgo.toISOString()
            });
        }
    }

    filterUsers() {
        const searchTerm = document.getElementById('searchInput').value.toLowerCase();
        const roleFilter = document.getElementById('roleFilter').value;
        
        this.filteredUsers = this.users.filter(user => {
            const matchesSearch = !searchTerm || 
                user.name.toLowerCase().includes(searchTerm) ||
                user.email.toLowerCase().includes(searchTerm) ||
                (user.company && user.company.toLowerCase().includes(searchTerm));
            
            const matchesRole = !roleFilter || user.role === roleFilter;
            
            return matchesSearch && matchesRole;
        });
        
        this.renderUsers();
    }

    renderUsers() {
        const tbody = document.getElementById('usersTableBody');
        const emptyState = document.getElementById('emptyState');
        
        if (this.filteredUsers.length === 0) {
            tbody.innerHTML = '';
            emptyState.classList.remove('hidden');
            return;
        }
        
        emptyState.classList.add('hidden');
        tbody.innerHTML = this.filteredUsers.map(user => UIRenderer.userRow(user, this)).join('');
    }

    openUserModal(userId = null) {
        this.currentEditUserId = userId;
        const user = userId ? this.users.find(u => u.id === userId) : null;
        
        const modal = document.getElementById('userModal');
        const title = document.getElementById('modalTitle');
        const deleteBtn = document.getElementById('deleteUserBtn');
        
        if (user) {
            title.innerHTML = '<i class="fas fa-user-edit"></i> Edit User';
            this.populateForm(user);
            deleteBtn.style.display = 'block';
        } else {
            title.innerHTML = '<i class="fas fa-user-plus"></i> Create User';
            this.clearForm();
            deleteBtn.style.display = 'none';
        }
        
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }

    closeModal() {
        document.getElementById('userModal').classList.add('hidden');
        document.body.style.overflow = '';
        this.currentEditUserId = null;
    }

    populateForm(user) {
        document.getElementById('userName').value = user.name || '';
        document.getElementById('userEmail').value = user.email || '';
        document.getElementById('userCompany').value = user.company || '';
        document.getElementById('userRole').value = user.role || 'user';
        document.getElementById('apiKey').value = user.api_key || '';
        document.getElementById('accountLocked').checked = user.status === 'locked';
        document.getElementById('newPassword').value = '';
    }

    clearForm() {
        document.getElementById('userForm').reset();
        document.getElementById('apiKey').value = '';
        document.getElementById('accountLocked').checked = false;
    }

    async saveUser() {
        try {
            const formData = {
                name: document.getElementById('userName').value.trim(),
                email: document.getElementById('userEmail').value.trim(),
                company: document.getElementById('userCompany').value.trim(),
                role: document.getElementById('userRole').value,
                locked: document.getElementById('accountLocked').checked
            };
            
            const password = document.getElementById('newPassword').value.trim();
            if (password) formData.password = password;
            
            this.validateUserData(formData, password);
            
            const result = this.currentEditUserId
                ? await this.api.put(`/users/${this.currentEditUserId}`, formData)
                : await this.api.post('/users', formData);
            
            if (result.success) {
                ToastManager.show(`User ${this.currentEditUserId ? 'updated' : 'created'} successfully`, 'success');
                this.closeModal();
                this.loadUsers();
                this.loadStats();
            } else {
                throw new Error(result.error || 'Operation failed');
            }
        } catch (error) {
            ToastManager.show(`Failed to save user: ${error.message}`, 'error');
        }
    }

    validateUserData(formData, password) {
        if (!formData.name || formData.name.length < 2) {
            throw new Error('Name must be at least 2 characters');
        }
        
        if (!formData.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
            throw new Error('Valid email address is required');
        }
        
        if (!this.currentEditUserId && !password) {
            throw new Error('Password is required for new users');
        }
        
        if (password && password.length < 8) {
            throw new Error('Password must be at least 8 characters');
        }
    }

    editUser(userId) {
        this.openUserModal(userId);
    }

    viewUserDetails(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return;
        
        const modalDiv = document.createElement('div');
        modalDiv.innerHTML = UIRenderer.userDetailsModal(user, this);
        const modal = modalDiv.firstElementChild;
        document.body.appendChild(modal);
        document.body.style.overflow = 'hidden';
        
        // Add event listeners for details modal
        modal.addEventListener('click', (e) => {
            if (e.target.classList.contains('close-details-modal') || e.target.closest('.close-details-modal')) {
                this.closeDetailsModal();
            }
            
            if (e.target.classList.contains('edit-from-details')) {
                const userId = e.target.dataset.userId;
                this.closeDetailsModal();
                this.editUser(userId);
            }
            
            if (e.target.classList.contains('copy-user-api')) {
                const apiKey = e.target.dataset.apiKey;
                this.copyUserApiKey(apiKey);
            }
            
            if (e.target.id === 'detailsModal') {
                this.closeDetailsModal();
            }
        });
    }

    closeDetailsModal() {
        document.getElementById('detailsModal')?.remove();
        document.body.style.overflow = '';
    }

    async copyUserApiKey(apiKey) {
        if (!apiKey) return;
        
        try {
            await navigator.clipboard.writeText(apiKey);
            ToastManager.show('API key copied to clipboard', 'success');
        } catch (error) {
            ToastManager.show('Failed to copy API key', 'error');
        }
    }

    confirmDeleteUser(userId) {
        const user = this.users.find(u => u.id === userId);
        if (user && confirm(`Are you sure you want to delete user "${user.name}"?\n\nEmail: ${user.email}\n\nThis action cannot be undone.`)) {
            this.deleteUserById(userId);
        }
    }

    async deleteUser() {
        if (this.currentEditUserId) {
            const user = this.users.find(u => u.id === this.currentEditUserId);
            if (user && confirm(`Are you sure you want to delete user "${user.name}"?\n\nThis action cannot be undone.`)) {
                await this.deleteUserById(this.currentEditUserId);
                this.closeModal();
            }
        }
    }

    async deleteUserById(userId) {
        try {
            const result = await this.api.delete(`/users/${userId}`);
            
            if (result.success) {
                ToastManager.show('User deleted successfully', 'success');
                this.loadUsers();
                this.loadStats();
            } else {
                throw new Error(result.error || 'Delete failed');
            }
        } catch (error) {
            ToastManager.show(`Failed to delete user: ${error.message}`, 'error');
        }
    }

    async regenerateApiKey() {
        if (this.currentEditUserId && confirm('Are you sure you want to regenerate the API key? The old key will become invalid.')) {
            try {
                const result = await this.api.post(`/users/${this.currentEditUserId}/regenerate-api-key`);
                
                if (result.success && result.data.api_key) {
                    document.getElementById('apiKey').value = result.data.api_key;
                    ToastManager.show('API key regenerated successfully', 'success');
                    
                    const user = this.users.find(u => u.id === this.currentEditUserId);
                    if (user) user.api_key = result.data.api_key;
                } else {
                    throw new Error(result.error || 'Failed to regenerate API key');
                }
            } catch (error) {
                ToastManager.show(`Failed to regenerate API key: ${error.message}`, 'error');
            }
        }
    }

    async copyApiKey() {
        const apiKey = document.getElementById('apiKey').value;
        if (apiKey) {
            try {
                await navigator.clipboard.writeText(apiKey);
                ToastManager.show('API key copied to clipboard', 'success');
            } catch (error) {
                ToastManager.show('Failed to copy API key', 'error');
            }
        }
    }

    showLoading(show) {
        const loadingState = document.getElementById('loadingState');
        const tableBody = document.getElementById('usersTableBody');
        
        if (show) {
            loadingState.classList.remove('hidden');
            tableBody.innerHTML = '';
        } else {
            loadingState.classList.add('hidden');
        }
    }

    startPeriodicRefresh() {
        // Refresh stats every 5 minutes (increased from 60 seconds)
        setInterval(() => this.loadStats(), 300000);
        
        // Check auth status every 5 minutes
        setInterval(() => {
            const auth = AuthManager.getAuth();
            if (!auth.user || !auth.apiKey) {
                window.location.href = '/user_auth/pages/login.html';
            }
        }, 300000);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.userManagement = new UserManagement();
});