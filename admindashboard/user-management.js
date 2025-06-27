// Enhanced User Management with Real Database Integration
// Replace the entire user-management.js file with this version

class UserManagement {
    constructor() {
        this.API_BASE_URL = 'http://127.0.0.1:5001/auth';
        this.users = [];
        this.filteredUsers = [];
        this.currentUser = null;
        this.pagination = {
            page: 1,
            limit: 50,
            total: 0,
            pages: 0
        };
        
        this.init();
    }

    init() {
        this.checkAuthAndInit();
    }

    checkAuthAndInit() {
        // Check if user is authenticated and is admin
        const userData = sessionStorage.getItem('fraudshield_user') || localStorage.getItem('fraudshield_persistent_user');
        const apiKey = sessionStorage.getItem('fraudshield_api_key') || localStorage.getItem('fraudshield_persistent_api_key');
        
        if (!userData || !apiKey) {
            console.error('❌ No authentication found');
            window.location.href = '/user_auth/pages/login.html?redirect=' + encodeURIComponent(window.location.pathname);
            return;
        }

        try {
            const user = JSON.parse(userData);
            if (user.user.role !== 'admin') {
                console.error('❌ Admin access required');
                alert('Admin access required for user management');
                window.location.href = '/index.html';
                return;
            }

            this.currentApiKey = apiKey;
            this.setupEventListeners();
            this.loadUsers();
            this.loadStats();
            
            console.log('✅ User Management initialized for admin:', user.user.email);
        } catch (error) {
            console.error('❌ Invalid user data:', error);
            window.location.href = '/user_auth/pages/login.html';
        }
    }

    getAuthHeaders() {
        return {
            'Authorization': `Bearer ${this.currentApiKey}`,
            'Content-Type': 'application/json'
        };
    }

    setupEventListeners() {
        // Search
        document.getElementById('searchInput').addEventListener('input', (e) => {
            this.filterUsers();
        });

        // Filter by role
        document.getElementById('roleFilter').addEventListener('change', () => {
            this.filterUsers();
        });

        // Refresh button
        document.getElementById('refreshBtn').addEventListener('click', () => {
            this.loadUsers();
            this.loadStats();
        });

        // Create user button
        document.getElementById('createUserBtn').addEventListener('click', () => {
            this.openUserModal();
        });

        // Modal close
        document.getElementById('closeModalBtn').addEventListener('click', () => {
            this.closeModal();
        });

        // Modal overlay click
        document.getElementById('userModal').addEventListener('click', (e) => {
            if (e.target.id === 'userModal') {
                this.closeModal();
            }
        });

        // User form submit
        document.getElementById('userForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveUser();
        });

        // Delete user
        document.getElementById('deleteUserBtn').addEventListener('click', () => {
            this.deleteUser();
        });

        // Cancel button
        document.getElementById('cancelBtn').addEventListener('click', () => {
            this.closeModal();
        });

        // API key actions
        document.getElementById('regenerateApiBtn').addEventListener('click', () => {
            this.regenerateApiKey();
        });

        document.getElementById('copyApiBtn').addEventListener('click', () => {
            this.copyApiKey();
        });
    }

    async loadUsers() {
        try {
            this.showLoading(true);
            
            const searchTerm = document.getElementById('searchInput').value.trim();
            const roleFilter = document.getElementById('roleFilter').value;
            
            // Build query parameters
            const params = new URLSearchParams({
                page: this.pagination.page.toString(),
                limit: this.pagination.limit.toString()
            });
            
            if (searchTerm) {
                params.append('search', searchTerm);
            }
            
            if (roleFilter) {
                params.append('role', roleFilter);
            }
            
            console.log('📡 Loading users from database...');
            
            const response = await fetch(`${this.API_BASE_URL}/users?${params}`, {
                method: 'GET',
                headers: this.getAuthHeaders()
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            
            if (result.success) {
                this.users = result.data.users || [];
                this.pagination = result.data.pagination || this.pagination;
                this.filteredUsers = [...this.users];
                
                console.log(`✅ Loaded ${this.users.length} users from database`);
                this.renderUsers();
            } else {
                throw new Error(result.error || 'Failed to load users');
            }
            
        } catch (error) {
            console.error('❌ Failed to load users:', error);
            this.showToast('Failed to load users: ' + error.message, 'error');
            this.users = [];
            this.filteredUsers = [];
            this.renderUsers();
        } finally {
            this.showLoading(false);
        }
    }

    async loadStats() {
        try {
            console.log('📊 Loading user statistics...');
            
            const response = await fetch(`${this.API_BASE_URL}/admin/stats`, {
                method: 'GET',
                headers: this.getAuthHeaders()
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            
            if (result.success) {
                const stats = result.data;
                
                // Update stat displays
                document.getElementById('totalUsers').textContent = stats.total_users || 0;
                document.getElementById('activeUsers').textContent = stats.active_today || 0;
                document.getElementById('adminUsers').textContent = stats.admin_users || 0;
                document.getElementById('newUsers').textContent = stats.new_this_week || 0;
                
                console.log('✅ Statistics loaded:', stats);
            } else {
                throw new Error(result.error || 'Failed to load stats');
            }
            
        } catch (error) {
            console.error('❌ Failed to load stats:', error);
            // Set fallback values
            document.getElementById('totalUsers').textContent = this.users.length;
            document.getElementById('activeUsers').textContent = '0';
            document.getElementById('adminUsers').textContent = this.users.filter(u => u.role === 'admin').length;
            document.getElementById('newUsers').textContent = '0';
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

    // Add this mock users method if needed for testing/demo
    getMockUsers() {
        return [
            {
                id: '1',
                name: 'John Doe',
                email: 'john@example.com',
                company: 'TechCorp',
                role: 'admin',
                status: 'active',
                last_login: '2025-06-26T10:30:00Z',
                created_at: '2025-06-20T10:00:00Z',
                api_key: 'fsk_admin_key_123'
            },
            {
                id: '2',
                name: 'Jane Smith',
                email: 'jane@company.com',
                company: 'StartupInc',
                role: 'user',
                status: 'active',
                last_login: '2025-06-25T15:45:00Z',
                created_at: '2025-06-18T09:00:00Z',
                api_key: 'fsk_user_key_456'
            },
            {
                id: '3',
                name: 'Bob Johnson',
                email: 'bob@business.org',
                company: 'Business Solutions',
                role: 'user',
                status: 'pending', // Changed from 'inactive' to 'pending'
                last_login: null, // Never logged in
                created_at: '2025-06-10T14:30:00Z',
                api_key: 'fsk_user_key_789'
            }
        ];
    }

    // Add this helper to fix user status based on login history
    fixUserStatus(user) {
        // If user never logged in, set status to pending
        if (!user.last_login) {
            user.status = 'pending';
        }
        // If user hasn't logged in for 30+ days, set to inactive
        else {
            const lastLogin = new Date(user.last_login);
            const thirtyDaysAgo = new Date();
            thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
            
            if (lastLogin < thirtyDaysAgo) {
                user.status = 'inactive';
            } else {
                user.status = 'active';
            }
        }
        return user;
    }

    // Update renderUsers to use fixUserStatus and getStatusText
    renderUsers() {
        const tbody = document.getElementById('usersTableBody');
        const emptyState = document.getElementById('emptyState');

        if (this.filteredUsers.length === 0) {
            tbody.innerHTML = '';
            emptyState.classList.remove('hidden');
            return;
        }

        emptyState.classList.add('hidden');

        tbody.innerHTML = this.filteredUsers.map(user => {
            // Fix user status based on login history
            const fixedUser = this.fixUserStatus({...user});
            
            return `
                <tr>
                    <td>
                        <div class="user-info">
                            <div class="user-avatar">
                                ${fixedUser.name.charAt(0).toUpperCase()}
                            </div>
                            <div class="user-details">
                                <h4>${fixedUser.name}</h4>
                                <p>ID: ${fixedUser.id}</p>
                            </div>
                       </div>
                   </td>
                   <td>${fixedUser.email}</td>
                   <td>
                       <span class="role-badge role-${fixedUser.role}">
                           ${fixedUser.role === 'admin' ? 'Administrator' : 'User'}
                       </span>
                   </td>
                   <td>${fixedUser.company || '-'}</td>
                   <td>${this.formatDate(fixedUser.last_login)}</td>
                   <td>
                       <span class="status-badge status-${fixedUser.status}">
                           <i class="fas fa-circle"></i>
                           ${this.getStatusText(fixedUser.status)}
                       </span>
                   </td>
                   <td>
                       <div class="action-buttons">
                           <button class="btn-icon" onclick="userManagement.editUser('${fixedUser.id}')" title="Edit User">
                               <i class="fas fa-edit"></i>
                           </button>
                           <button class="btn-icon" onclick="userManagement.viewUser('${fixedUser.id}')" title="View Details">
                               <i class="fas fa-eye"></i>
                           </button>
                           <button class="btn-icon danger" onclick="userManagement.confirmDeleteUser('${fixedUser.id}')" title="Delete User">
                               <i class="fas fa-trash"></i>
                           </button>
                       </div>
                   </td>
               </tr>
           `;
        }).join('');
    }

    // Add this helper for status text
    getStatusText(status) {
        const statusMap = {
            'active': 'Active',
            'inactive': 'Inactive', 
            'pending': 'Pending',
            'locked': 'Locked'
        };
        return statusMap[status] || status.charAt(0).toUpperCase() + status.slice(1);
    }

    formatDate(dateString) {
        if (!dateString) return 'Never';
        
        const date = new Date(dateString);
        const now = new Date();
        const diffTime = Math.abs(now - date);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

        if (diffDays === 1) return 'Today';
        if (diffDays === 2) return 'Yesterday';
        if (diffDays <= 7) return `${diffDays} days ago`;
        
        return date.toLocaleDateString();
    }

    openUserModal(userId = null) {
        this.currentUser = userId ? this.users.find(u => u.id === userId) : null;
        
        const modal = document.getElementById('userModal');
        const title = document.getElementById('modalTitle');
        const deleteBtn = document.getElementById('deleteUserBtn');

        if (this.currentUser) {
            title.innerHTML = '<i class="fas fa-user-edit"></i> Edit User';
            this.populateForm(this.currentUser);
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
        this.currentUser = null;
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
            if (password) {
                formData.password = password;
            }

            // Validation
            if (!formData.name || formData.name.length < 2) {
                throw new Error('Name must be at least 2 characters');
            }

            if (!formData.email || !this.isValidEmail(formData.email)) {
                throw new Error('Valid email address is required');
            }

            if (!this.currentUser && !password) {
                throw new Error('Password is required for new users');
            }

            if (password && password.length < 8) {
                throw new Error('Password must be at least 8 characters');
            }

            let response;
            let successMessage;

            if (this.currentUser) {
                // Update existing user
                response = await fetch(`${this.API_BASE_URL}/users/${this.currentUser.id}`, {
                    method: 'PUT',
                    headers: this.getAuthHeaders(),
                    body: JSON.stringify(formData)
                });
                successMessage = 'User updated successfully';
            } else {
                // Create new user
                response = await fetch(`${this.API_BASE_URL}/users`, {
                    method: 'POST',
                    headers: this.getAuthHeaders(),
                    body: JSON.stringify(formData)
                });
                successMessage = 'User created successfully';
            }

            if (!response.ok) {
                const errorResult = await response.json();
                throw new Error(errorResult.error || `HTTP ${response.status}`);
            }

            const result = await response.json();
            
            if (result.success) {
                this.showToast(successMessage, 'success');
                this.closeModal();
                this.loadUsers();
                this.loadStats();
            } else {
                throw new Error(result.error || 'Operation failed');
            }

        } catch (error) {
            console.error('❌ Failed to save user:', error);
            this.showToast('Failed to save user: ' + error.message, 'error');
        }
    }

    editUser(userId) {
        this.openUserModal(userId);
    }

    viewUser(userId) {
        const user = this.users.find(u => u.id === userId);
        if (user) {
            const details = `
User Details:
• Name: ${user.name}
• Email: ${user.email}
• Role: ${user.role}
• Company: ${user.company || 'N/A'}
• Status: ${user.status}
• Created: ${user.created_at ? new Date(user.created_at).toLocaleDateString() : 'Unknown'}
• Last Login: ${this.formatDate(user.last_login)}
• API Key: ${user.api_key ? user.api_key.substring(0, 20) + '...' : 'None'}
            `;
            alert(details);
        }
    }

    confirmDeleteUser(userId) {
        const user = this.users.find(u => u.id === userId);
        if (user && confirm(`Are you sure you want to delete user "${user.name}"?\n\nEmail: ${user.email}\n\nThis action cannot be undone.`)) {
            this.deleteUserById(userId);
        }
    }

    async deleteUser() {
        if (this.currentUser && confirm(`Are you sure you want to delete user "${this.currentUser.name}"?\n\nThis action cannot be undone.`)) {
            await this.deleteUserById(this.currentUser.id);
            this.closeModal();
        }
    }

    async deleteUserById(userId) {
        try {
            console.log('🗑️ Deleting user:', userId);
            
            const response = await fetch(`${this.API_BASE_URL}/users/${userId}`, {
                method: 'DELETE',
                headers: this.getAuthHeaders()
            });

            if (!response.ok) {
                const errorResult = await response.json();
                throw new Error(errorResult.error || `HTTP ${response.status}`);
            }

            const result = await response.json();
            
            if (result.success) {
                this.showToast('User deleted successfully', 'success');
                this.loadUsers();
                this.loadStats();
            } else {
                throw new Error(result.error || 'Delete failed');
            }

        } catch (error) {
            console.error('❌ Failed to delete user:', error);
            this.showToast('Failed to delete user: ' + error.message, 'error');
        }
    }

    async regenerateApiKey() {
        if (this.currentUser && confirm('Are you sure you want to regenerate the API key? The old key will become invalid.')) {
            try {
                const response = await fetch(`${this.API_BASE_URL}/users/${this.currentUser.id}`, {
                    method: 'PUT',
                    headers: this.getAuthHeaders(),
                    body: JSON.stringify({ regenerate_api_key: true })
                });

                if (!response.ok) {
                    const errorResult = await response.json();
                    throw new Error(errorResult.error || `HTTP ${response.status}`);
                }

                const result = await response.json();
                
                if (result.success && result.data.api_key) {
                    document.getElementById('apiKey').value = result.data.api_key;
                    this.showToast('API key regenerated successfully', 'success');
                } else {
                    throw new Error(result.error || 'Failed to regenerate API key');
                }

            } catch (error) {
                console.error('❌ Failed to regenerate API key:', error);
                this.showToast('Failed to regenerate API key: ' + error.message, 'error');
            }
        }
    }

    async copyApiKey() {
        const apiKey = document.getElementById('apiKey').value;
        if (apiKey) {
            try {
                await navigator.clipboard.writeText(apiKey);
                this.showToast('API key copied to clipboard', 'success');
            } catch (error) {
                console.error('❌ Failed to copy API key:', error);
                this.showToast('Failed to copy API key', 'error');
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

    showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <div style="display: flex; align-items: center; gap: 0.5rem;">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                <span>${this.escapeHtml(message)}</span>
            </div>
        `;

        container.appendChild(toast);

        // Auto remove after 5 seconds
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 5000);
    }

    // Utility methods
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.userManagement = new UserManagement();
});