async function login(username, password) {
  try {
    const response = await fetch('http://localhost:3000/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (response.ok) {
      // Save token in memory (or sessionStorage for page refresh)
      sessionStorage.setItem('authToken', data.token);
      showDashboard(data.user);
    } else {
      alert('Login failed: ' + data.error);
    }
  } catch (err) {
    alert('Network error');
  }
}

function getAuthHeader() {
  const token = sessionStorage.getItem('authToken');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// Example: Fetch admin data
async function loadAdminDashboard() {
  const res = await fetch('http://localhost:3000/api/admin/dashboard', {
    headers: getAuthHeader()
  });
  if (res.ok) {
    const data = await res.json();
    document.getElementById('content').innerText = data.message;
  } else {
    document.getElementById('content').innerText = 'Access denied!';
  }
}

// ============================================================================
// GLOBAL VARIABLES & CONSTANTS
// ============================================================================

const STORAGE_KEY = 'ipt_demo_v1';
let currentUser = null;

window.db = { accounts: [], departments: [], employees: [], requests: [] };

// ============================================================================
// STORAGE MANAGEMENT
// ============================================================================

function loadFromStorage() {
    try {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
            window.db = JSON.parse(stored);
            ['accounts', 'departments', 'employees', 'requests'].forEach(key => {
                if (!Array.isArray(window.db[key])) window.db[key] = [];
            });
            
            const adminIndex = window.db.accounts.findIndex(acc => acc.email === 'admin@example.com');
            if (adminIndex === -1) {
                if (window.db.accounts.length === 0) {
                    seedInitialData();
                    saveToStorage();
                } else {
                    window.db.accounts.push({
                        email: 'admin@example.com', password: 'Password123!',
                        firstName: 'Admin', lastName: 'User', role: 'admin', verified: true
                    });
                    saveToStorage();
                }
            } else if (window.db.accounts[adminIndex].password !== 'Password123!') {
                Object.assign(window.db.accounts[adminIndex], {
                    password: 'Password123!', role: 'admin', verified: true,
                    firstName: window.db.accounts[adminIndex].firstName || 'Admin',
                    lastName: window.db.accounts[adminIndex].lastName || 'User'
                });
                saveToStorage();
            }
            
            if (window.db.departments.length === 0) {
                window.db.departments = [
                    { id: 1, name: 'Engineering', description: 'Software development and engineering' },
                    { id: 2, name: 'HR', description: 'Human resources and talent management' }
                ];
                saveToStorage();
            }
        } else {
            seedInitialData();
            saveToStorage();
        }
    } catch (error) {
        console.error('Error loading from storage:', error);
        seedInitialData();
        saveToStorage();
    }
}

function saveToStorage() {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(window.db));
    } catch (error) {
        console.error('Error saving to storage:', error);
        showToast('Error saving data', 'error');
    }
}

function seedInitialData() {
    window.db = {
        accounts: [{
            email: 'admin@example.com', password: 'Password123!',
            firstName: 'Admin', lastName: 'User', role: 'admin', verified: true
        }],
        departments: [
            { id: 1, name: 'Engineering', description: 'Software development and engineering' },
            { id: 2, name: 'HR', description: 'Human resources and talent management' }
        ],
        employees: [],
        requests: []
    };
}

// ============================================================================
// AUTHENTICATION
// ============================================================================

function setAuthState(isAuth, user = null) {
    currentUser = user;
    const body = document.body;
    if (isAuth && user) {
        body.classList.remove('not-authenticated');
        body.classList.add('authenticated');
        if (user.role === 'admin') body.classList.add('is-admin');
        else body.classList.remove('is-admin');
        const navUsername = document.getElementById('nav-username');
        if (navUsername) navUsername.textContent = `${user.firstName} ${user.lastName}`;
    } else {
        body.classList.remove('authenticated', 'is-admin');
        body.classList.add('not-authenticated');
        currentUser = null;
    }
}

function checkAuth() {
    const authToken = localStorage.getItem('auth_token');
    if (authToken) {
        const account = window.db.accounts.find(acc => acc.email === authToken && acc.verified);
        if (account) {
            setAuthState(true, account);
            return true;
        } else {
            localStorage.removeItem('auth_token');
            setAuthState(false);
        }
    }
    return false;
}

function logout() {
    localStorage.removeItem('auth_token');
    setAuthState(false);
    navigateTo('/');
    showToast('Logged out successfully', 'success');
}

// ============================================================================
// ROUTING
// ============================================================================

function navigateTo(hash) {
    if (!hash.startsWith('/')) hash = '/' + hash;
    window.location.hash = '#' + hash;
}

function handleRouting() {
    const hash = window.location.hash.slice(1) || '/';
    const protectedRoutes = ['/profile', '/requests', '/employees', '/departments', '/accounts'];
    const adminRoutes = ['/employees', '/departments', '/accounts'];
    const isProtected = protectedRoutes.some(route => hash.startsWith(route));
    const isAdminRoute = adminRoutes.some(route => hash.startsWith(route));
    
    if (isProtected && !currentUser) {
        showToast('Please login to access this page', 'warning');
        navigateTo('/login');
        return;
    }
    
    if (isAdminRoute && (!currentUser || currentUser.role !== 'admin')) {
        showToast('Access denied. Admin only.', 'error');
        navigateTo('/');
        return;
    }
    
    document.querySelectorAll('.page').forEach(page => page.classList.remove('active'));
    
    const pageMap = {
        '/': 'home-page', '/register': 'register-page', '/verify-email': 'verify-email-page',
        '/login': 'login-page', '/profile': 'profile-page', '/employees': 'employees-page',
        '/departments': 'departments-page', '/accounts': 'accounts-page', '/requests': 'requests-page'
    };
    
    const pageId = pageMap[hash] || 'home-page';
    const targetPage = document.getElementById(pageId);
    
    if (targetPage) {
        targetPage.classList.add('active');
        if (pageId === 'verify-email-page') {
            const unverifiedEmail = localStorage.getItem('unverified_email');
            const verifyEmailAddress = document.getElementById('verify-email-address');
            if (verifyEmailAddress && unverifiedEmail) {
                verifyEmailAddress.textContent = unverifiedEmail;
            } else if (!unverifiedEmail) {
                showToast('No pending verification found', 'warning');
                navigateTo('/register');
                return;
            }
        }
        renderPageContent(pageId);
    } else {
        document.getElementById('home-page').classList.add('active');
    }
    
    if (hash === '/' && currentUser) {
        const homeUsername = document.getElementById('home-username');
        if (homeUsername) homeUsername.textContent = `${currentUser.firstName} ${currentUser.lastName}`;
    }
}

function renderPageContent(pageId) {
    const renderers = {
        'profile-page': renderProfile,
        'employees-page': renderEmployeesTable,
        'departments-page': renderDepartmentsTable,
        'accounts-page': renderAccountsTable,
        'requests-page': renderRequestsTable
    };
    if (renderers[pageId]) renderers[pageId]();
}

// ============================================================================
// REGISTRATION & VERIFICATION
// ============================================================================

function handleRegister(e) {
    e.preventDefault();
    const firstName = document.getElementById('reg-firstname').value.trim();
    const lastName = document.getElementById('reg-lastname').value.trim();
    const email = document.getElementById('reg-email').value.trim();
    const password = document.getElementById('reg-password').value;
    const errorDiv = document.getElementById('register-error');
    
    if (password.length < 6) {
        errorDiv.textContent = 'Password must be at least 6 characters long';
        errorDiv.style.display = 'block';
        return;
    }
    
    if (window.db.accounts.find(acc => acc.email === email)) {
        errorDiv.textContent = 'Email already registered';
        errorDiv.style.display = 'block';
        return;
    }
    
    window.db.accounts.push({ email, password, firstName, lastName, role: 'user', verified: false });
    saveToStorage();
    localStorage.setItem('unverified_email', email);
    navigateTo('/verify-email');
    showToast('Registration successful! Please verify your email.', 'success');
}

function handleEmailVerification() {
    const email = localStorage.getItem('unverified_email');
    if (!email) {
        showToast('No pending verification found', 'error');
        navigateTo('/register');
        return;
    }
    const account = window.db.accounts.find(acc => acc.email === email);
    if (!account) {
        showToast('Account not found', 'error');
        navigateTo('/register');
        return;
    }
    account.verified = true;
    saveToStorage();
    localStorage.removeItem('unverified_email');
    showToast('Email verified successfully! You can now login.', 'success');
    navigateTo('/login');
}

// ============================================================================
// LOGIN
// ============================================================================

function handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    const errorDiv = document.getElementById('login-error');
    
    if (!window.db || !window.db.accounts) {
        errorDiv.textContent = 'Database not initialized. Please refresh the page.';
        errorDiv.style.display = 'block';
        return;
    }
    
    const accountByEmail = window.db.accounts.find(acc => acc.email === email);
    if (!accountByEmail) {
        errorDiv.textContent = 'Invalid email or email not found';
        errorDiv.style.display = 'block';
        return;
    }
    
    const storedPassword = (accountByEmail.password || '').trim();
    
    if (email === 'admin@example.com' && storedPassword !== 'Password123!') {
        accountByEmail.password = 'Password123!';
        saveToStorage();
    }
    
    const finalStoredPassword = (accountByEmail.password || '').trim();
    if (finalStoredPassword !== password) {
        errorDiv.textContent = email === 'admin@example.com' 
            ? 'Invalid password. Admin default password is: Password123!' 
            : 'Invalid password. Note: Password is case-sensitive.';
        errorDiv.style.display = 'block';
        return;
    }
    
    if (!accountByEmail.verified) {
        errorDiv.textContent = 'Email not verified. Please verify your email first.';
        errorDiv.style.display = 'block';
        return;
    }
    
    localStorage.setItem('auth_token', email);
    setAuthState(true, accountByEmail);
    errorDiv.style.display = 'none';
    showToast('Login successful!', 'success');
    navigateTo('/profile');
}

// ============================================================================
// PROFILE PAGE
// ============================================================================

function renderProfile() {
    if (!currentUser) return;
    const profileContent = document.getElementById('profile-content');
    profileContent.innerHTML = `
        <div class="profile-card">
            <h3>${currentUser.firstName} ${currentUser.lastName}</h3>
            <hr>
            <p><strong>Email:</strong> ${currentUser.email}</p>
            <p><strong>Role:</strong> <span class="badge bg-${currentUser.role === 'admin' ? 'danger' : 'primary'}">${currentUser.role.toUpperCase()}</span></p>
            <p><strong>Verified:</strong> ${currentUser.verified ? '✅ Yes' : '❌ No'}</p>
            <button class="btn btn-primary mt-3" onclick="alert('Edit profile feature coming soon!')">Edit Profile</button>
        </div>
    `;
}

// ============================================================================
// ACCOUNTS MANAGEMENT (Admin)
// ============================================================================

function renderAccountsTable() {
    const container = document.getElementById('accounts-table-container');
    if (window.db.accounts.length === 0) {
        container.innerHTML = '<p>No accounts found.</p>';
        return;
    }
    
    let html = `<table class="table table-striped table-hover"><thead><tr>
        <th>Name</th><th>Email</th><th>Role</th><th>Verified</th><th>Actions</th>
    </tr></thead><tbody>`;
    
    window.db.accounts.forEach(account => {
        html += `<tr>
            <td>${account.firstName} ${account.lastName}</td>
            <td>${account.email}</td>
            <td><span class="badge bg-${account.role === 'admin' ? 'danger' : 'primary'}">${account.role}</span></td>
            <td>${account.verified ? '✅' : '❌'}</td>
            <td>
                <button class="btn btn-sm btn-outline-primary" onclick="editAccount('${account.email}')">Edit</button>
                <button class="btn btn-sm btn-outline-warning" onclick="resetPassword('${account.email}')">Reset PW</button>
                <button class="btn btn-sm btn-outline-danger" onclick="deleteAccount('${account.email}')">Delete</button>
            </td>
        </tr>`;
    });
    
    container.innerHTML = html + '</tbody></table>';
}

function editAccount(email) {
    const account = window.db.accounts.find(acc => acc.email === email);
    if (!account) return;
    document.getElementById('account-modal-title').textContent = 'Edit Account';
    document.getElementById('account-email-edit').value = email;
    document.getElementById('account-firstname').value = account.firstName;
    document.getElementById('account-lastname').value = account.lastName;
    document.getElementById('account-email').value = account.email;
    document.getElementById('account-email').disabled = true;
    document.getElementById('account-password').value = '';
    document.getElementById('account-role').value = account.role;
    document.getElementById('account-verified').checked = account.verified;
    new bootstrap.Modal(document.getElementById('account-modal')).show();
}

function resetPassword(email) {
    const account = window.db.accounts.find(acc => acc.email === email);
    if (!account) return;
    const newPassword = prompt('Enter new password (min 6 characters):');
    if (!newPassword || newPassword.length < 6) {
        showToast('Password must be at least 6 characters', 'error');
        return;
    }
    account.password = newPassword;
    saveToStorage();
    showToast('Password reset successfully', 'success');
    renderAccountsTable();
}

function deleteAccount(email) {
    if (email === currentUser.email) {
        showToast('Cannot delete your own account', 'error');
        return;
    }
    if (!confirm(`Are you sure you want to delete the account for ${email}?`)) return;
    window.db.accounts = window.db.accounts.filter(acc => acc.email !== email);
    window.db.employees = window.db.employees.filter(emp => emp.userEmail !== email);
    saveToStorage();
    showToast('Account deleted successfully', 'success');
    renderAccountsTable();
}

function saveAccount() {
    const editEmail = document.getElementById('account-email-edit').value;
    const firstName = document.getElementById('account-firstname').value.trim();
    const lastName = document.getElementById('account-lastname').value.trim();
    const email = document.getElementById('account-email').value.trim();
    const password = document.getElementById('account-password').value;
    const role = document.getElementById('account-role').value;
    const verified = document.getElementById('account-verified').checked;
    const isEdit = !!editEmail;
    
    if (isEdit) {
        const account = window.db.accounts.find(acc => acc.email === editEmail);
        if (account) {
            Object.assign(account, { firstName, lastName, role, verified });
            if (password && password.length >= 6) account.password = password;
        }
    } else {
        if (window.db.accounts.find(acc => acc.email === email)) {
            showToast('Email already exists', 'error');
            return;
        }
        if (!password || password.length < 6) {
            showToast('Password must be at least 6 characters', 'error');
            return;
        }
        window.db.accounts.push({ email, password, firstName, lastName, role, verified });
    }
    
    saveToStorage();
    renderAccountsTable();
    bootstrap.Modal.getInstance(document.getElementById('account-modal')).hide();
    document.getElementById('account-form').reset();
    document.getElementById('account-email-edit').value = '';
    document.getElementById('account-email').disabled = false;
    document.getElementById('account-modal-title').textContent = 'Add Account';
    showToast(`Account ${isEdit ? 'updated' : 'created'} successfully`, 'success');
}

// ============================================================================
// DEPARTMENTS MANAGEMENT (Admin)
// ============================================================================

function renderDepartmentsTable() {
    const container = document.getElementById('departments-table-container');
    if (window.db.departments.length === 0) {
        container.innerHTML = '<p>No departments found.</p>';
        return;
    }
    
    let html = `<table class="table table-striped table-hover"><thead><tr>
        <th>Name</th><th>Description</th><th>Actions</th>
    </tr></thead><tbody>`;
    
    window.db.departments.forEach(dept => {
        html += `<tr>
            <td>${dept.name}</td>
            <td>${dept.description || '—'}</td>
            <td><button class="btn btn-sm btn-outline-primary" onclick="alert('Edit department not implemented yet')">Edit</button></td>
        </tr>`;
    });
    
    container.innerHTML = html + '</tbody></table>';
}

// ============================================================================
// EMPLOYEES MANAGEMENT (Admin)
// ============================================================================

function renderEmployeesTable() {
    const container = document.getElementById('employees-table-container');
    if (window.db.employees.length === 0) {
        container.innerHTML = '<p>No employees found.</p>';
        return;
    }
    
    let html = `<table class="table table-striped table-hover"><thead><tr>
        <th>ID</th><th>User (Email)</th><th>Position</th><th>Department</th><th>Hire Date</th><th>Actions</th>
    </tr></thead><tbody>`;
    
    window.db.employees.forEach(employee => {
        const dept = window.db.departments.find(d => d.id === employee.departmentId);
        html += `<tr>
            <td>${employee.id}</td>
            <td>${employee.userEmail}</td>
            <td>${employee.position}</td>
            <td>${dept ? dept.name : '—'}</td>
            <td>${employee.hireDate || '—'}</td>
            <td>
                <button class="btn btn-sm btn-outline-primary" onclick="editEmployee('${employee.id}')">Edit</button>
                <button class="btn btn-sm btn-outline-danger" onclick="deleteEmployee('${employee.id}')">Delete</button>
            </td>
        </tr>`;
    });
    
    container.innerHTML = html + '</tbody></table>';
    populateDepartmentDropdown();
}

function populateDepartmentDropdown() {
    const select = document.getElementById('employee-department');
    select.innerHTML = '<option value="">Select Department</option>';
    window.db.departments.forEach(dept => {
        const option = document.createElement('option');
        option.value = dept.id;
        option.textContent = dept.name;
        select.appendChild(option);
    });
}

function editEmployee(employeeId) {
    const employee = window.db.employees.find(emp => emp.id === employeeId);
    if (!employee) return;
    document.getElementById('employee-modal-title').textContent = 'Edit Employee';
    document.getElementById('employee-id-edit').value = employeeId;
    document.getElementById('employee-id').value = employee.id;
    document.getElementById('employee-email').value = employee.userEmail;
    document.getElementById('employee-position').value = employee.position;
    document.getElementById('employee-department').value = employee.departmentId;
    document.getElementById('employee-hiredate').value = employee.hireDate || '';
    populateDepartmentDropdown();
    new bootstrap.Modal(document.getElementById('employee-modal')).show();
}

function deleteEmployee(employeeId) {
    if (!confirm('Are you sure you want to delete this employee?')) return;
    window.db.employees = window.db.employees.filter(emp => emp.id !== employeeId);
    saveToStorage();
    showToast('Employee deleted successfully', 'success');
    renderEmployeesTable();
}

function saveEmployee() {
    const editId = document.getElementById('employee-id-edit').value;
    const id = document.getElementById('employee-id').value.trim();
    const userEmail = document.getElementById('employee-email').value.trim();
    const position = document.getElementById('employee-position').value.trim();
    const departmentId = parseInt(document.getElementById('employee-department').value);
    const hireDate = document.getElementById('employee-hiredate').value;
    
    if (!window.db.accounts.find(acc => acc.email === userEmail)) {
        showToast('User email does not exist in accounts', 'error');
        return;
    }
    if (!window.db.departments.find(d => d.id === departmentId)) {
        showToast('Please select a valid department', 'error');
        return;
    }
    
    const isEdit = !!editId;
    if (isEdit) {
        const employee = window.db.employees.find(emp => emp.id === editId);
        if (employee) {
            if (id !== editId && window.db.employees.find(emp => emp.id === id)) {
                showToast('Employee ID already exists', 'error');
                return;
            }
            Object.assign(employee, { id, userEmail, position, departmentId, hireDate });
        }
    } else {
        if (window.db.employees.find(emp => emp.id === id)) {
            showToast('Employee ID already exists', 'error');
            return;
        }
        window.db.employees.push({ id, userEmail, position, departmentId, hireDate });
    }
    
    saveToStorage();
    renderEmployeesTable();
    bootstrap.Modal.getInstance(document.getElementById('employee-modal')).hide();
    document.getElementById('employee-form').reset();
    document.getElementById('employee-id-edit').value = '';
    document.getElementById('employee-modal-title').textContent = 'Add Employee';
    showToast(`Employee ${isEdit ? 'updated' : 'created'} successfully`, 'success');
}

// ============================================================================
// REQUESTS MANAGEMENT
// ============================================================================

function renderRequestsTable() {
    if (!currentUser) return;
    const container = document.getElementById('requests-table-container');
    const userRequests = window.db.requests.filter(req => req.employeeEmail === currentUser.email);
    
    if (userRequests.length === 0) {
        container.innerHTML = '<p>No requests found. Create your first request!</p>';
        return;
    }
    
    let html = `<table class="table table-striped table-hover"><thead><tr>
        <th>Date</th><th>Type</th><th>Items</th><th>Status</th>
    </tr></thead><tbody>`;
    
    userRequests.forEach(request => {
        const itemsHtml = request.items.map(item => `${item.name} (${item.quantity})`).join(', ');
        const statusClass = {
            'Pending': 'badge-pending',
            'Approved': 'badge-approved',
            'Rejected': 'badge-rejected'
        }[request.status] || 'badge-secondary';
        
        html += `<tr>
            <td>${request.date}</td>
            <td>${request.type}</td>
            <td>${itemsHtml}</td>
            <td><span class="badge ${statusClass}">${request.status}</span></td>
        </tr>`;
    });
    
    container.innerHTML = html + '</tbody></table>';
}

function addRequestItem() {
    const container = document.getElementById('request-items-container');
    if (container.children.length === 0) {
        showToast('Please initialize the form first', 'warning');
        return;
    }
    
    const newItem = document.createElement('div');
    newItem.className = 'request-item mb-2';
    newItem.innerHTML = `<div class="row g-2">
        <div class="col-md-6"><input type="text" class="form-control" placeholder="Item name" required></div>
        <div class="col-md-3"><input type="number" class="form-control" placeholder="Quantity" min="1" required></div>
        <div class="col-md-3"><button type="button" class="btn btn-danger btn-sm remove-item-btn">×</button></div>
    </div>`;
    container.appendChild(newItem);
    
    newItem.querySelector('.remove-item-btn').addEventListener('click', function() {
        if (container.children.length > 1) newItem.remove();
        else showToast('At least one item is required', 'warning');
    });
}

function initializeRequestItemHandlers() {
    const container = document.getElementById('request-items-container');
    container.querySelectorAll('.remove-item-btn').forEach(btn => {
        const newBtn = btn.cloneNode(true);
        btn.parentNode.replaceChild(newBtn, btn);
        newBtn.addEventListener('click', function() {
            if (container.children.length > 1) this.closest('.request-item').remove();
            else showToast('At least one item is required', 'warning');
        });
    });
}

function saveRequest() {
    if (!currentUser) return;
    const type = document.getElementById('request-type').value;
    const itemElements = document.querySelectorAll('#request-items-container .request-item');
    
    if (!type) {
        showToast('Please select a request type', 'error');
        return;
    }
    if (itemElements.length === 0) {
        showToast('Please add at least one item', 'error');
        return;
    }
    
    const items = [];
    let isValid = true;
    itemElements.forEach(itemEl => {
        const nameInput = itemEl.querySelector('input[type="text"]');
        const qtyInput = itemEl.querySelector('input[type="number"]');
        const name = nameInput.value.trim();
        const quantity = parseInt(qtyInput.value);
        if (!name || !quantity || quantity < 1) {
            isValid = false;
            return;
        }
        items.push({ name, quantity });
    });
    
    if (!isValid) {
        showToast('Please fill in all item fields correctly', 'error');
        return;
    }
    
    window.db.requests.push({
        id: Date.now().toString(), type, items,
        status: 'Pending', date: new Date().toLocaleDateString(),
        employeeEmail: currentUser.email
    });
    saveToStorage();
    renderRequestsTable();
    bootstrap.Modal.getInstance(document.getElementById('request-modal')).hide();
    document.getElementById('request-form').reset();
    document.getElementById('request-items-container').innerHTML = `<div class="request-item mb-2">
        <div class="row g-2">
            <div class="col-md-6"><input type="text" class="form-control" placeholder="Item name" required></div>
            <div class="col-md-3"><input type="number" class="form-control" placeholder="Quantity" min="1" required></div>
            <div class="col-md-3"><button type="button" class="btn btn-danger btn-sm remove-item-btn">×</button></div>
        </div>
    </div>`;
    initializeRequestItemHandlers();
    showToast('Request submitted successfully', 'success');
}

// ============================================================================
// TOAST NOTIFICATIONS
// ============================================================================

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toastId = 'toast-' + Date.now();
    const bgColors = {
        'success': 'bg-success', 'error': 'bg-danger',
        'warning': 'bg-warning', 'info': 'bg-info'
    };
    
    const toastHtml = `<div id="${toastId}" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
        <div class="toast-header ${bgColors[type] || 'bg-info'} text-white">
            <strong class="me-auto">${type.charAt(0).toUpperCase() + type.slice(1)}</strong>
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast"></button>
        </div>
        <div class="toast-body">${message}</div>
    </div>`;
    
    container.insertAdjacentHTML('beforeend', toastHtml);
    const toastElement = document.getElementById(toastId);
    const toast = new bootstrap.Toast(toastElement, { autohide: true, delay: 3000 });
    toast.show();
    toastElement.addEventListener('hidden.bs.toast', () => toastElement.remove());
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

document.addEventListener('DOMContentLoaded', function() {
    loadFromStorage();
    checkAuth();
    
    if (!window.location.hash) navigateTo('/');
    handleRouting();
    window.addEventListener('hashchange', handleRouting);
    
    const forms = {
        'register-form': handleRegister,
        'login-form': handleLogin
    };
    Object.entries(forms).forEach(([id, handler]) => {
        const form = document.getElementById(id);
        if (form) form.addEventListener('submit', handler);
        else console.error(`${id} not found`);
    });
    
    document.getElementById('verify-email-btn').addEventListener('click', function() {
        const email = localStorage.getItem('unverified_email');
        if (email) {
            document.getElementById('verify-email-address').textContent = email;
            handleEmailVerification();
        } else {
            showToast('No pending verification found', 'error');
            navigateTo('/register');
        }
    });
    
    document.getElementById('logout-btn').addEventListener('click', function(e) {
        e.preventDefault();
        logout();
    });
    
    document.getElementById('add-account-btn').addEventListener('click', function() {
        document.getElementById('account-modal-title').textContent = 'Add Account';
        document.getElementById('account-form').reset();
        document.getElementById('account-email-edit').value = '';
        document.getElementById('account-email').disabled = false;
    });
    document.getElementById('save-account-btn').addEventListener('click', saveAccount);
    
    document.getElementById('add-employee-btn').addEventListener('click', function() {
        document.getElementById('employee-modal-title').textContent = 'Add Employee';
        document.getElementById('employee-form').reset();
        document.getElementById('employee-id-edit').value = '';
        populateDepartmentDropdown();
    });
    document.getElementById('save-employee-btn').addEventListener('click', saveEmployee);
    
    document.getElementById('add-department-btn').addEventListener('click', function() {
        alert('Add department feature not implemented yet');
    });
    
    document.getElementById('add-request-btn').addEventListener('click', function() {
        document.getElementById('request-form').reset();
        document.getElementById('request-items-container').innerHTML = `<div class="request-item mb-2">
            <div class="row g-2">
                <div class="col-md-6"><input type="text" class="form-control" placeholder="Item name" required></div>
                <div class="col-md-3"><input type="number" class="form-control" placeholder="Quantity" min="1" required></div>
                <div class="col-md-3"><button type="button" class="btn btn-danger btn-sm remove-item-btn">×</button></div>
            </div>
        </div>`;
        initializeRequestItemHandlers();
    });
    
    document.getElementById('add-item-btn').addEventListener('click', addRequestItem);
    document.getElementById('save-request-btn').addEventListener('click', saveRequest);
});