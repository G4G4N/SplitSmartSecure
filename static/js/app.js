// SplitSmart Web Application JavaScript

// API Base URL
const API_BASE = '';

// State Management
let currentUser = null;
let isLoggedIn = false;
let payerChart = null;
let trendChart = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

// Initialize Application
function initializeApp() {
    // Setup event listeners
    setupAuthTabs();
    setupAuthForms();
    setupExpenseForm();
    setupButtons();
    
    // Check initial status
    checkStatus();
}

// Initialize Charts
function initializeCharts() {
    // Destroy existing charts if they exist
    if (payerChart) payerChart.destroy();
    if (trendChart) trendChart.destroy();
    
    // Payer Chart (Pie Chart)
    const payerCtx = document.getElementById('payerChart');
    if (payerCtx) {
        payerChart = new Chart(payerCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        'rgba(99, 102, 241, 0.8)',
                        'rgba(139, 92, 246, 0.8)',
                        'rgba(16, 185, 129, 0.8)',
                        'rgba(245, 158, 11, 0.8)',
                        'rgba(239, 68, 68, 0.8)',
                        'rgba(59, 130, 246, 0.8)',
                        'rgba(236, 72, 153, 0.8)',
                    ],
                    borderColor: [
                        'rgba(99, 102, 241, 1)',
                        'rgba(139, 92, 246, 1)',
                        'rgba(16, 185, 129, 1)',
                        'rgba(245, 158, 11, 1)',
                        'rgba(239, 68, 68, 1)',
                        'rgba(59, 130, 246, 1)',
                        'rgba(236, 72, 153, 1)',
                    ],
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#cbd5e1',
                            padding: 15,
                            font: {
                                size: 12
                            }
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed || 0;
                                return `${label}: $${value.toFixed(2)}`;
                            }
                        }
                    }
                }
            }
        });
    }
    
    // Trend Chart (Line Chart)
    const trendCtx = document.getElementById('trendChart');
    if (trendCtx) {
        trendChart = new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Daily Spending',
                    data: [],
                    borderColor: 'rgba(99, 102, 241, 1)',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    pointBackgroundColor: 'rgba(99, 102, 241, 1)',
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: true,
                        labels: {
                            color: '#cbd5e1'
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `$${context.parsed.y.toFixed(2)}`;
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: '#cbd5e1',
                            callback: function(value) {
                                return '$' + value.toFixed(0);
                            }
                        },
                        grid: {
                            color: 'rgba(71, 85, 105, 0.3)'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#cbd5e1'
                        },
                        grid: {
                            color: 'rgba(71, 85, 105, 0.3)'
                        }
                    }
                }
            }
        });
    }
}

// Setup Auth Tabs
function setupAuthTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            
            // Update active tab button
            tabButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // Update active tab content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(`${tab}Tab`).classList.add('active');
        });
    });
}

// Setup Auth Forms
function setupAuthForms() {
    // Login Form
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('loginUsername').value.trim();
        const password = document.getElementById('loginPassword').value;
        
        if (!username) {
            showToast('Please enter a username', 'error');
            return;
        }
        if (!password) {
            showToast('Please enter a password', 'error');
            return;
        }
        await login(username, password);
    });
    
    // Register Form
    document.getElementById('registerForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('registerUsername').value.trim();
        const password = document.getElementById('registerPassword').value;
        const passwordConfirm = document.getElementById('registerPasswordConfirm').value;
        
        if (!username) {
            showToast('Please enter a username', 'error');
            return;
        }
        if (!password) {
            showToast('Please enter a password', 'error');
            return;
        }
        if (password.length < 6) {
            showToast('Password must be at least 6 characters long', 'error');
            return;
        }
        if (password !== passwordConfirm) {
            showToast('Passwords do not match', 'error');
            return;
        }
        await register(username, password);
    });
}

// Setup Expense Form
function setupExpenseForm() {
    document.getElementById('expenseForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const payer = document.getElementById('payer').value.trim();
        const amount = parseFloat(document.getElementById('amount').value);
        const description = document.getElementById('description').value.trim();
        
        if (!payer || !amount || amount <= 0 || !description) {
            showToast('Please fill in all fields with valid data', 'error');
            return;
        }
        
        await addExpense(payer, amount, description);
        
        // Reset form
        document.getElementById('expenseForm').reset();
    });
}

// Setup Buttons
function setupButtons() {
    // Logout Button
    document.getElementById('logoutBtn').addEventListener('click', async () => {
        await logout();
    });
    
    // Refresh Ledger
    document.getElementById('refreshLedgerBtn').addEventListener('click', async () => {
        await loadLedger();
    });
    
    // Refresh Balances
    document.getElementById('refreshBalancesBtn').addEventListener('click', async () => {
        await loadBalances();
    });
    
    // Verify Tampering
    document.getElementById('verifyTamperingBtn').addEventListener('click', async () => {
        await verifyTampering();
    });
    
    // Refresh Analytics
    document.getElementById('refreshAnalyticsBtn').addEventListener('click', async () => {
        await loadAnalytics();
    });
    
    // Refresh Blockchain
    document.getElementById('refreshBlockchainBtn').addEventListener('click', async () => {
        await loadBlockchain();
    });
}

// Check Status
async function checkStatus() {
    try {
        const response = await fetch(`${API_BASE}/api/status`, {
            credentials: 'include'
        });
        const data = await response.json();
        
        if (data.success && data.logged_in) {
            currentUser = data.username;
            isLoggedIn = data.has_session;
            updateUI();
            
            if (isLoggedIn) {
                await loadLedger();
                await loadBalances();
            }
        }
    } catch (error) {
        console.error('Status check failed:', error);
    }
}

// Register User
async function register(username, password) {
    try {
        showToast('Registering user...', 'warning');
        
        const response = await fetch(`${API_BASE}/api/register`, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(data.message, 'success');
            // Auto-login after registration
            await login(username, password);
        } else {
            showToast(data.error || 'Registration failed', 'error');
        }
    } catch (error) {
        showToast('Registration failed: ' + error.message, 'error');
    }
}

// Login User
async function login(username, password) {
    try {
        showToast('Logging in...', 'warning');
        
        const response = await fetch(`${API_BASE}/api/login`, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUser = username;
            isLoggedIn = true;
            showToast(data.message, 'success');
            updateUI();
            await loadLedger();
            await loadBalances();
            await loadAnalytics();
            await loadBlockchain();
            
            // Clear password fields
            document.getElementById('loginPassword').value = '';
        } else {
            showToast(data.error || 'Login failed', 'error');
        }
    } catch (error) {
        showToast('Login failed: ' + error.message, 'error');
    }
}

// Logout User
async function logout() {
    try {
        const response = await fetch(`${API_BASE}/api/logout`, {
            method: 'POST',
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUser = null;
            isLoggedIn = false;
            showToast('Logged out successfully', 'success');
            updateUI();
        }
    } catch (error) {
        showToast('Logout failed: ' + error.message, 'error');
    }
}

// Add Expense
async function addExpense(payer, amount, description) {
    try {
        showToast('Submitting expense...', 'warning');
        
        const response = await fetch(`${API_BASE}/api/add_expense`, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ payer, amount, description })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(data.message, 'success');
            // Refresh ledger, balances, and analytics
            await loadLedger();
            await loadBalances();
            await loadAnalytics();
        } else {
            showToast(data.error || 'Failed to add expense', 'error');
        }
    } catch (error) {
        showToast('Failed to add expense: ' + error.message, 'error');
    }
}

// Load Ledger
async function loadLedger() {
    const ledgerContent = document.getElementById('ledgerContent');
    ledgerContent.innerHTML = '<div class="loading-spinner"><i class="fas fa-spinner fa-spin"></i><p>Loading ledger...</p></div>';
    
    try {
        const response = await fetch(`${API_BASE}/api/ledger`, {
            credentials: 'include'
        });
        const data = await response.json();
        
        if (data.success && data.entries) {
            displayLedger(data.entries);
        } else {
            ledgerContent.innerHTML = '<div class="empty-state"><i class="fas fa-book"></i><p>No ledger entries found</p></div>';
        }
    } catch (error) {
        ledgerContent.innerHTML = `<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><p>Error loading ledger: ${error.message}</p></div>`;
    }
}

// Display Ledger
function displayLedger(entries) {
    const ledgerContent = document.getElementById('ledgerContent');
    
    if (entries.length === 0) {
        ledgerContent.innerHTML = '<div class="empty-state"><i class="fas fa-book"></i><p>No ledger entries yet</p></div>';
        return;
    }
    
    ledgerContent.innerHTML = entries.map(entry => `
        <div class="ledger-entry">
            <div class="ledger-entry-header">
                <span class="ledger-entry-id">Entry #${entry.id}</span>
                <span class="ledger-entry-amount">$${parseFloat(entry.amount).toFixed(2)}</span>
            </div>
            <div class="ledger-entry-details">
                <strong>Payer:</strong> <span>${entry.payer}</span>
                <strong>Description:</strong> <span>${entry.description}</span>
                <strong>Timestamp:</strong> <span>${new Date(entry.timestamp).toLocaleString()}</span>
                <strong>Counter:</strong> <span>${entry.counter}</span>
            </div>
            <div class="ledger-entry-hash">
                <strong>Hash:</strong> ${entry.entry_hash.substring(0, 32)}...
            </div>
        </div>
    `).join('');
}

// Load Balances
async function loadBalances() {
    const balancesContent = document.getElementById('balancesContent');
    balancesContent.innerHTML = '<div class="loading-spinner"><i class="fas fa-spinner fa-spin"></i><p>Loading balances...</p></div>';
    
    try {
        const response = await fetch(`${API_BASE}/api/balances`, {
            credentials: 'include'
        });
        const data = await response.json();
        
        if (data.success && data.balances) {
            displayBalances(data.balances);
        } else {
            balancesContent.innerHTML = '<div class="empty-state"><i class="fas fa-balance-scale"></i><p>No balance data available</p></div>';
        }
    } catch (error) {
        balancesContent.innerHTML = `<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><p>Error loading balances: ${error.message}</p></div>`;
    }
}

// Display Balances
function displayBalances(balances) {
    const balancesContent = document.getElementById('balancesContent');
    
    if (!balances || Object.keys(balances).length === 0) {
        balancesContent.innerHTML = '<div class="empty-state"><i class="fas fa-balance-scale"></i><p>No balances to display</p></div>';
        return;
    }
    
    balancesContent.innerHTML = Object.entries(balances).map(([user, balance]) => {
        const isPositive = balance >= 0;
        return `
            <div class="balance-item ${isPositive ? 'positive' : 'negative'}">
                <span class="balance-label">${user}</span>
                <span class="balance-amount ${isPositive ? 'positive' : 'negative'}">
                    ${isPositive ? '+' : ''}$${Math.abs(balance).toFixed(2)}
                </span>
            </div>
        `;
    }).join('');
}

// Verify Tampering
async function verifyTampering() {
    const resultDiv = document.getElementById('tamperingResult');
    resultDiv.innerHTML = '<div class="loading-spinner"><i class="fas fa-spinner fa-spin"></i><p>Verifying ledger integrity...</p></div>';
    resultDiv.classList.add('show');
    
    try {
        const response = await fetch(`${API_BASE}/api/verify_tampering`, {
            credentials: 'include'
        });
        const data = await response.json();
        
        if (data.success) {
            if (data.is_valid) {
                resultDiv.className = 'tampering-result show valid';
                resultDiv.innerHTML = `
                    <div style="display: flex; align-items: center; gap: 0.75rem;">
                        <i class="fas fa-check-circle" style="font-size: 1.5rem;"></i>
                        <div>
                            <strong>Ledger Integrity Verified</strong>
                            <p style="margin: 0.25rem 0 0 0;">All entries are valid. No tampering detected.</p>
                        </div>
                    </div>
                `;
                showToast('Ledger integrity verified - No tampering detected', 'success');
            } else {
                resultDiv.className = 'tampering-result show invalid';
                resultDiv.innerHTML = `
                    <div style="display: flex; align-items: center; gap: 0.75rem;">
                        <i class="fas fa-exclamation-triangle" style="font-size: 1.5rem;"></i>
                        <div>
                            <strong>Tampering Detected!</strong>
                            <p style="margin: 0.25rem 0 0 0;">${data.error || 'Ledger integrity violation detected'}</p>
                        </div>
                    </div>
                `;
                showToast('Tampering detected in ledger!', 'error');
            }
        } else {
            resultDiv.className = 'tampering-result show invalid';
            resultDiv.innerHTML = `<div>Error: ${data.error}</div>`;
        }
    } catch (error) {
        resultDiv.className = 'tampering-result show invalid';
        resultDiv.innerHTML = `<div>Error verifying tampering: ${error.message}</div>`;
    }
}

// Load Analytics
async function loadAnalytics() {
    try {
        const response = await fetch(`${API_BASE}/api/analytics`, {
            method: 'GET',
            credentials: 'include',  // Include cookies for session
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        // Check if response is OK
        if (!response.ok) {
            if (response.status === 401) {
                // Session expired, redirect to login
                showToast('Session expired. Please login again.', 'error');
                isLoggedIn = false;
                currentUser = null;
                updateUI();
                return;
            }
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        if (data.success && data.analytics) {
            displayAnalytics(data.analytics);
        } else {
            console.error('Failed to load analytics:', data.error || data.message);
            showToast('Failed to load analytics: ' + (data.error || data.message || 'Unknown error'), 'error');
        }
    } catch (error) {
        console.error('Error loading analytics:', error);
        showToast('Error loading analytics: ' + error.message, 'error');
    }
}

// Display Analytics
function displayAnalytics(analytics) {
    // Update summary cards
    document.getElementById('totalAmount').textContent = `$${analytics.total_amount.toFixed(2)}`;
    document.getElementById('totalEntries').textContent = analytics.total_expenses;
    document.getElementById('averageExpense').textContent = `$${analytics.average_expense.toFixed(2)}`;
    document.getElementById('mostActivePayer').textContent = analytics.most_active_payer || '-';
    
    // Update Payer Chart
    if (payerChart && analytics.by_payer) {
        const payers = Object.keys(analytics.by_payer);
        const amounts = Object.values(analytics.by_payer);
        
        payerChart.data.labels = payers;
        payerChart.data.datasets[0].data = amounts;
        payerChart.update();
    }
    
    // Update Trend Chart
    if (trendChart && analytics.expense_trends) {
        const dates = analytics.expense_trends.map(t => {
            const date = new Date(t.date);
            return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        });
        const amounts = analytics.expense_trends.map(t => t.amount);
        
        trendChart.data.labels = dates;
        trendChart.data.datasets[0].data = amounts;
        trendChart.update();
    }
    
    // Display Largest Expense
    const largestDiv = document.getElementById('largestExpense');
    if (analytics.largest_expense) {
        const exp = analytics.largest_expense;
        largestDiv.innerHTML = `
            <div class="expense-amount">$${exp.amount.toFixed(2)}</div>
            <div class="expense-payer">Paid by: ${exp.payer}</div>
            <div class="expense-description">${exp.description}</div>
            <div class="expense-date">${new Date(exp.timestamp).toLocaleString()}</div>
        `;
    } else {
        largestDiv.innerHTML = '<p class="loading-text">No expenses yet</p>';
    }
    
    // Display Smallest Expense
    const smallestDiv = document.getElementById('smallestExpense');
    if (analytics.smallest_expense) {
        const exp = analytics.smallest_expense;
        smallestDiv.innerHTML = `
            <div class="expense-amount">$${exp.amount.toFixed(2)}</div>
            <div class="expense-payer">Paid by: ${exp.payer}</div>
            <div class="expense-description">${exp.description}</div>
            <div class="expense-date">${new Date(exp.timestamp).toLocaleString()}</div>
        `;
    } else {
        smallestDiv.innerHTML = '<p class="loading-text">No expenses yet</p>';
    }
    
    // Display Recent Expenses
    const recentDiv = document.getElementById('recentExpenses');
    if (analytics.recent_entries && analytics.recent_entries.length > 0) {
        recentDiv.innerHTML = analytics.recent_entries.map(entry => `
            <div class="recent-expense-item">
                <div class="expense-header">
                    <span class="expense-payer-small">${entry.payer}</span>
                    <span class="expense-amount-small">$${parseFloat(entry.amount).toFixed(2)}</span>
                </div>
                <div class="expense-description-small">${entry.description}</div>
                <div class="expense-date-small">${new Date(entry.timestamp).toLocaleString()}</div>
            </div>
        `).join('');
    } else {
        recentDiv.innerHTML = '<p class="loading-text">No recent expenses</p>';
    }
    
    // Display Spending by User
    const userSpendingDiv = document.getElementById('spendingByUser');
    if (analytics.by_user && Object.keys(analytics.by_user).length > 0) {
        const sortedUsers = Object.entries(analytics.by_user)
            .sort((a, b) => b[1] - a[1]);
        
        userSpendingDiv.innerHTML = sortedUsers.map(([user, amount]) => `
            <div class="user-spending-item">
                <span class="user-name">${user}</span>
                <span class="user-amount">$${amount.toFixed(2)}</span>
            </div>
        `).join('');
    } else {
        userSpendingDiv.innerHTML = '<p class="loading-text">No user spending data</p>';
    }
}

// Update UI based on login status
function updateUI() {
    const authSection = document.getElementById('authSection');
    const dashboardSection = document.getElementById('dashboardSection');
    const statusText = document.getElementById('statusText');
    const statusIndicator = document.querySelector('.status-indicator');
    const logoutBtn = document.getElementById('logoutBtn');
    
    if (isLoggedIn && currentUser) {
        authSection.style.display = 'none';
        dashboardSection.style.display = 'grid';
        statusText.textContent = `Logged in as ${currentUser}`;
        statusIndicator.classList.add('active');
        logoutBtn.style.display = 'block';
        
        // Initialize charts when dashboard is shown
        setTimeout(() => {
            initializeCharts();
            loadAnalytics();
            loadBlockchain();
        }, 100);
    } else {
        authSection.style.display = 'block';
        dashboardSection.style.display = 'none';
        statusText.textContent = 'Not logged in';
        statusIndicator.classList.remove('active');
        logoutBtn.style.display = 'none';
        
        // Destroy charts when logged out
        if (payerChart) {
            payerChart.destroy();
            payerChart = null;
        }
        if (trendChart) {
            trendChart.destroy();
            trendChart = null;
        }
    }
}

// Load Blockchain
async function loadBlockchain() {
    try {
        const response = await fetch(`${API_BASE}/api/blockchain`, {
            credentials: 'include'
        });
        const data = await response.json();
        
        if (data.success && data.blockchain) {
            displayBlockchain(data.blockchain, data.blocks || []);
        } else {
            console.error('Failed to load blockchain:', data.error);
        }
    } catch (error) {
        console.error('Error loading blockchain:', error);
    }
}

// Display Blockchain
function displayBlockchain(blockchainInfo, blocks) {
    const blockchainContent = document.getElementById('blockchainContent');
    
    if (!blockchainInfo || blockchainInfo.total_blocks === 0) {
        blockchainContent.innerHTML = '<div class="empty-state"><i class="fas fa-link"></i><p>No blocks in blockchain yet</p></div>';
        return;
    }
    
    // Blockchain stats
    const statsHtml = `
        <div class="blockchain-stats">
            <div class="blockchain-stat">
                <div class="blockchain-stat-value">${blockchainInfo.total_blocks}</div>
                <div class="blockchain-stat-label">Total Blocks</div>
            </div>
            <div class="blockchain-stat">
                <div class="blockchain-stat-value">${blockchainInfo.chain_length}</div>
                <div class="blockchain-stat-label">Chain Length</div>
            </div>
            <div class="blockchain-stat">
                <div class="blockchain-stat-value" style="color: ${blockchainInfo.is_valid ? 'var(--success-color)' : 'var(--error-color)'}">
                    ${blockchainInfo.is_valid ? '✓ Valid' : '✗ Invalid'}
                </div>
                <div class="blockchain-stat-label">Chain Status</div>
            </div>
            <div class="blockchain-stat">
                <div class="blockchain-stat-value" style="font-size: 0.9rem; word-break: break-all;">
                    ${blockchainInfo.genesis_hash.substring(0, 16)}...
                </div>
                <div class="blockchain-stat-label">Genesis Hash</div>
            </div>
        </div>
    `;
    
    // Blockchain chain
    const blocksHtml = blocks.map(block => `
        <div class="blockchain-block">
            <div class="block-header">
                <span class="block-height">Block #${block.block_height !== undefined ? block.block_height : block.id}</span>
                <span class="block-hash">${(block.block_hash || block.entry_hash).substring(0, 32)}...</span>
            </div>
            <div class="block-details">
                <strong>Payer:</strong> <span>${block.payer}</span>
                <strong>Amount:</strong> <span>$${parseFloat(block.amount).toFixed(2)}</span>
                <strong>Description:</strong> <span>${block.description}</span>
                <strong>Timestamp:</strong> <span>${new Date(block.timestamp).toLocaleString()}</span>
                ${block.prev_hash ? `<strong>Prev Hash:</strong> <span style="font-family: monospace; font-size: 0.8rem;">${block.prev_hash.substring(0, 16)}...</span>` : ''}
            </div>
        </div>
    `).join('');
    
    blockchainContent.innerHTML = `
        ${statsHtml}
        <div class="blockchain-chain">
            ${blocksHtml}
        </div>
    `;
}

// Show Toast Notification
function showToast(message, type = 'success') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icon = type === 'success' ? 'check-circle' : 
                 type === 'error' ? 'exclamation-circle' : 
                 'info-circle';
    
    toast.innerHTML = `
        <i class="fas fa-${icon}"></i>
        <div class="toast-message">${message}</div>
        <button class="toast-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    container.appendChild(toast);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        toast.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// Add slideOutRight animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOutRight {
        from {
            opacity: 1;
            transform: translateX(0);
        }
        to {
            opacity: 0;
            transform: translateX(100%);
        }
    }
`;
document.head.appendChild(style);

