class UserManagement {
    constructor() {
        this.API_BASE_URL = 'http://127.0.0.1:5001/auth';
        this.users = [];
        this.filteredUsers = [];
        this.currentUser = null;
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadUsers();
        this.loadStats();
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
            
            // For now, we'll use mock data since the API endpoint doesn't exist yet
            this.users = this.getMockUsers();
            this.filteredUsers = [...this.users];
            
            this.renderUsers();
            this.showLoading(false);
            
        } catch (error) {
            console.error('Failed to load users:', error);
            this.showToast('Failed to load users', 'error');
            this.showLoading(false);
        }
    }

    async loadStats() {
        try {
            // Mock stats for now
            const stats = {
                total: this.users.length,
                active: this.users.filter(u => u.status === 'active').length,
                admins: this.users.filter(u => u.role === 'admin').length,
                newThisWeek: this.users.filter(u => {
                    const weekAgo = new Date();
                    weekAgo.setDate(weekAgo.getDate() - 7);
                    return new Date(u.created_at) > weekAgo;
                }).length
            };

            document.getElementById('totalUsers').textContent = stats.total;
            document.getElementById('activeUsers').textContent = stats.active;
            document.getElementById('adminUsers').textContent = stats.admins;
            document.getElementById('newUsers').textContent = stats.newThisWeek;
            
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }

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
                status: 'inactive',
                last_login: '2025-06-15T08:20:00Z',
                created_at: '2025-06-10T14:30:00Z',
                api_key: 'fsk_user_key_789'
            }
        ];
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

        tbody.innerHTML = this.filteredUsers.map(user => `
            <tr>
                <td>
                    <div class="user-info">
                        <div class="user-avatar">
                            ${user.name.charAt(0).toUpperCase()}
                        </div>
                        <div class="user-details">
                            <h4>${user.name}</h4>
                            <p>ID: ${user.id}</p
                        </div>
                   </div>
               </td>
               <td>${user.email}</td>
               <td>
                   <span class="role-badge role-${user.role}">
                       ${user.role === 'admin' ? 'Administrator' : 'User'}
                   </span>
               </td>
               <td>${user.company || '-'}</td>
               <td>${this.formatDate(user.last_login)}</td>
               <td>
                   <span class="status-badge status-${user.status}">
                       <i class="fas fa-circle"></i>
                       ${user.status.charAt(0).toUpperCase() + user.status.slice(1)}
                   </span>
               </td>
               <td>
                   <div class="action-buttons">
                       <button class="btn-icon" onclick="userManagement.editUser('${user.id}')" title="Edit User">
                           <i class="fas fa-edit"></i>
                       </button>
                       <button class="btn-icon" onclick="userManagement.viewUser('${user.id}')" title="View Details">
                           <i class="fas fa-eye"></i>
                       </button>
                       <button class="btn-icon danger" onclick="userManagement.confirmDeleteUser('${user.id}')" title="Delete User">
                           <i class="fas fa-trash"></i>
                       </button>
                   </div>
               </td>
           </tr>
       `).join('');
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
       document.getElementById('userName').value = user.name;
       document.getElementById('userEmail').value = user.email;
       document.getElementById('userCompany').value = user.company || '';
       document.getElementById('userRole').value = user.role;
       document.getElementById('apiKey').value = user.api_key;
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
               name: document.getElementById('userName').value,
               email: document.getElementById('userEmail').value,
               company: document.getElementById('userCompany').value,
               role: document.getElementById('userRole').value,
               password: document.getElementById('newPassword').value,
               locked: document.getElementById('accountLocked').checked
           };

           if (this.currentUser) {
               // Update existing user
               await this.updateUser(this.currentUser.id, formData);
               this.showToast('User updated successfully', 'success');
           } else {
               // Create new user
               await this.createUser(formData);
               this.showToast('User created successfully', 'success');
           }

           this.closeModal();
           this.loadUsers();
           this.loadStats();

       } catch (error) {
           console.error('Failed to save user:', error);
           this.showToast('Failed to save user', 'error');
       }
   }

   async createUser(userData) {
       // Mock implementation - replace with actual API call
       const newUser = {
           id: Date.now().toString(),
           ...userData,
           status: userData.locked ? 'locked' : 'active',
           created_at: new Date().toISOString(),
           last_login: null,
           api_key: `fsk_${Math.random().toString(36).substring(2, 15)}`
       };
       
       this.users.push(newUser);
       return newUser;
   }

   async updateUser(userId, userData) {
       // Mock implementation - replace with actual API call
       const userIndex = this.users.findIndex(u => u.id === userId);
       if (userIndex !== -1) {
           this.users[userIndex] = {
               ...this.users[userIndex],
               ...userData,
               status: userData.locked ? 'locked' : 'active'
           };
       }
   }

   editUser(userId) {
       this.openUserModal(userId);
   }

   viewUser(userId) {
       const user = this.users.find(u => u.id === userId);
       if (user) {
           alert(`User Details:\nName: ${user.name}\nEmail: ${user.email}\nRole: ${user.role}\nCompany: ${user.company || 'N/A'}\nStatus: ${user.status}`);
       }
   }

   confirmDeleteUser(userId) {
       const user = this.users.find(u => u.id === userId);
       if (user && confirm(`Are you sure you want to delete user "${user.name}"?\n\nThis action cannot be undone.`)) {
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
           // Mock implementation - replace with actual API call
           this.users = this.users.filter(u => u.id !== userId);
           
           this.showToast('User deleted successfully', 'success');
           this.loadUsers();
           this.loadStats();

       } catch (error) {
           console.error('Failed to delete user:', error);
           this.showToast('Failed to delete user', 'error');
       }
   }

   async regenerateApiKey() {
       if (this.currentUser && confirm('Are you sure you want to regenerate the API key? The old key will become invalid.')) {
           try {
               // Mock implementation - replace with actual API call
               const newApiKey = `fsk_${Math.random().toString(36).substring(2, 15)}`;
               document.getElementById('apiKey').value = newApiKey;
               
               this.showToast('API key regenerated successfully', 'success');

           } catch (error) {
               console.error('Failed to regenerate API key:', error);
               this.showToast('Failed to regenerate API key', 'error');
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
               console.error('Failed to copy API key:', error);
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
               <span>${message}</span>
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
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
   window.userManagement = new UserManagement();
});