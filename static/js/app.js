// SplitSmart Web Application JavaScript

// API Base URL
const API_BASE = '';

// State Management
let currentUser = null;
let isLoggedIn = false;
let integrityKey = null;  // For request integrity verification (modification protection)
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
    
    // AI Security: refresh, dry-run test form and presets
    document.getElementById('refreshAISecurityBtn').addEventListener('click', async () => {
        await loadAISecurity();
    });
    document.getElementById('aiTestForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        await runAITest();
    });
    document.querySelectorAll('.ai-preset').forEach(btn => {
        btn.addEventListener('click', () => {
            document.getElementById('aiTestDescription').value = btn.dataset.desc;
            document.getElementById('aiTestAmount').value = btn.dataset.amount;
            if (!document.getElementById('aiTestPayer').value) {
                document.getElementById('aiTestPayer').value = currentUser || '';
            }
        });
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
            
            // Retrieve integrity key from server or localStorage
            integrityKey = data.integrity_key || localStorage.getItem('integrityKey') || null;
            if (integrityKey && !data.integrity_key) {
                // If we got it from localStorage but server doesn't have it, clear it
                localStorage.removeItem('integrityKey');
                integrityKey = null;
            } else if (integrityKey) {
                // Store in localStorage for persistence
                localStorage.setItem('integrityKey', integrityKey);
            }
            
            updateUI();
            
            if (isLoggedIn) {
                await loadLedger();
                await loadBalances();
            }
        } else {
            // Not logged in - clear integrity key
            integrityKey = null;
            localStorage.removeItem('integrityKey');
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
            integrityKey = data.integrity_key || null;  // Store integrity key for HMAC
            // Store in localStorage for persistence across page refreshes
            if (integrityKey) {
                localStorage.setItem('integrityKey', integrityKey);
            }
            showToast(data.message, 'success');
            updateUI();
            await loadLedger();
            await loadBalances();
            await loadAnalytics();
            await loadBlockchain();
            await loadAISecurity();
            
            // Clear password fields
            document.getElementById('loginPassword').value = '';
        } else {
            showToast(data.error || 'Login failed', 'error');
            if (data.security_notice) {
                showToast(data.security_notice, 'warning');
            }
            if (data.retry_after) {
                showToast(`Blocked by AI Security. Try again in ${data.retry_after}s.`, 'error');
            }
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
            integrityKey = null;  // Clear integrity key on logout
            localStorage.removeItem('integrityKey');  // Remove from localStorage
            showToast('Logged out successfully', 'success');
            updateUI();
        }
    } catch (error) {
        showToast('Logout failed: ' + error.message, 'error');
    }
}

// Compute HMAC for request integrity (modification protection)
async function computeHMAC(message, key) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const messageData = encoder.encode(message);
    
    // Import key for HMAC
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    
    // Compute HMAC
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
    
    // Convert to hex string
    const hashArray = Array.from(new Uint8Array(signature));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Add Expense
async function addExpense(payer, amount, description) {
    try {
        showToast('Submitting expense...', 'warning');
        
        const requestBody = JSON.stringify({ payer, amount, description });
        
        // Compute HMAC for request integrity (modification protection)
        let headers = {
            'Content-Type': 'application/json'
        };
        
        // Get integrity key from variable or localStorage
        const keyToUse = integrityKey || localStorage.getItem('integrityKey');
        
        if (keyToUse) {
            try {
                const hmac = await computeHMAC(requestBody, keyToUse);
                headers['X-Request-HMAC'] = hmac;
                // Update the variable if we got it from localStorage
                if (!integrityKey && keyToUse) {
                    integrityKey = keyToUse;
                }
            } catch (error) {
                console.error('HMAC computation failed:', error);
                // Continue without HMAC - server will reject, but at least we tried
            }
        } else {
            console.warn('No integrity key available for HMAC computation');
        }
        
        const response = await fetch(`${API_BASE}/api/add_expense`, {
            method: 'POST',
            credentials: 'include',
            headers: headers,
            body: requestBody
        });
        
        const data = await response.json();
        
        if (data.success) {
            showToast(data.message, 'success');
            if (data.security) {
                showRiskToast(data.security, data.warning);
            }
            // Refresh ledger, balances, analytics and the AI panel
            await loadLedger();
            await loadBalances();
            await loadAnalytics();
            await loadAISecurity();
        } else {
            showToast(data.error || 'Failed to add expense', 'error');
            if (data.security) {
                showRiskToast(data.security);
                await loadAISecurity();
            }
            if (data.retry_after) {
                showToast(`Blocked by AI Security. Try again in ${data.retry_after}s.`, 'error');
            }
        }
    } catch (error) {
        showToast('Failed to add expense: ' + error.message, 'error');
    }
}

// Show the AI risk verdict for a submitted expense
function showRiskToast(security, warning) {
    const level = (security.risk_level || 'LOW').toUpperCase();
    const score = Number(security.risk_score || 0).toFixed(0);
    const reasons = (security.reasons || []).slice(0, 2).map(escapeHtml).join('; ');
    const type = security.action === 'block' ? 'error' : (security.action === 'flag' ? 'warning' : 'success');
    const headline = warning ? escapeHtml(warning) : `AI Security: ${level} risk (score ${score}/100)`;
    showToast(`${headline}${reasons ? '<br><small>' + reasons + '</small>' : ''}`, type);
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
    
    if (!balances) {
        balancesContent.innerHTML = '<div class="empty-state"><i class="fas fa-balance-scale"></i><p>No balances to display</p></div>';
        return;
    }
    
    const detailed = balances.detailed || {};
    const simplified = balances.simplified || [];
    
    // If no balances at all
    if (Object.keys(detailed).length === 0 && simplified.length === 0) {
        balancesContent.innerHTML = '<div class="empty-state"><i class="fas fa-balance-scale"></i><p>No balances to display</p></div>';
        return;
    }
    
    let html = '';
    
    // Calculate summary statistics
    const totalOwed = simplified.reduce((sum, debt) => sum + debt.amount, 0);
    const totalDebts = Object.values(detailed).filter(b => b < 0).reduce((sum, b) => sum + Math.abs(b), 0);
    const totalCredits = Object.values(detailed).filter(b => b > 0).reduce((sum, b) => sum + b, 0);
    
    // Display summary
    if (simplified.length > 0 || Object.keys(detailed).length > 0) {
        html += `
            <div class="balance-summary">
                <div class="summary-card">
                    <div class="summary-icon" style="background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);">
                        <i class="fas fa-arrow-down"></i>
                    </div>
                    <div class="summary-info">
                        <h4>Total Owed</h4>
                        <p>$${totalOwed.toFixed(2)}</p>
                    </div>
                </div>
                <div class="summary-card">
                    <div class="summary-icon" style="background: linear-gradient(135deg, #10b981 0%, #059669 100%);">
                        <i class="fas fa-arrow-up"></i>
                    </div>
                    <div class="summary-info">
                        <h4>Total to Receive</h4>
                        <p>$${totalCredits.toFixed(2)}</p>
                    </div>
                </div>
                <div class="summary-card">
                    <div class="summary-icon" style="background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);">
                        <i class="fas fa-exchange-alt"></i>
                    </div>
                    <div class="summary-info">
                        <h4>Transactions</h4>
                        <p>${simplified.length}</p>
                    </div>
                </div>
            </div>
        `;
    }
    
    // Display simplified balances (who owes whom) - Splitwise style
    if (simplified.length > 0) {
        html += `
            <div class="balances-section">
                <h3 class="balances-section-title">
                    <i class="fas fa-exchange-alt"></i> Who Owes Whom
                </h3>
                <div class="simplified-balances">
                    ${simplified.map(debt => `
                        <div class="debt-item">
                            <div class="debt-arrow">
                                <div class="debt-from">
                                    <i class="fas fa-user"></i>
                                    <span class="debt-person">${escapeHtml(debt.from)}</span>
                                </div>
                                <div class="debt-arrow-icon">
                                    <i class="fas fa-arrow-right"></i>
                                </div>
                                <div class="debt-to">
                                    <i class="fas fa-user"></i>
                                    <span class="debt-person">${escapeHtml(debt.to)}</span>
                                </div>
                            </div>
                            <div class="debt-amount">
                                <span class="debt-amount-value">$${debt.amount.toFixed(2)}</span>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    } else {
        html += `
            <div class="balances-section">
                <div class="all-settled">
                    <i class="fas fa-check-circle"></i>
                    <p>All settled! No one owes anyone.</p>
                </div>
            </div>
        `;
    }
    
    // Display detailed balances (net balances)
    if (Object.keys(detailed).length > 0) {
        html += `
            <div class="balances-section">
                <h3 class="balances-section-title">
                    <i class="fas fa-chart-line"></i> Net Balances
                </h3>
                <div class="detailed-balances">
                    ${Object.entries(detailed).map(([user, balance]) => {
                        const isPositive = balance >= 0;
                        return `
                            <div class="balance-item ${isPositive ? 'positive' : 'negative'}">
                                <div class="balance-info">
                                    <i class="fas fa-user"></i>
                                    <span class="balance-label">${escapeHtml(user)}</span>
                                </div>
                                <span class="balance-amount ${isPositive ? 'positive' : 'negative'}">
                                    ${isPositive ? '<i class="fas fa-arrow-up"></i>' : '<i class="fas fa-arrow-down"></i>'}
                                    ${isPositive ? '+' : ''}$${Math.abs(balance).toFixed(2)}
                                </span>
                            </div>
                        `;
                    }).join('')}
                </div>
            </div>
        `;
    }
    
    balancesContent.innerHTML = html;
}

// Helper function to escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
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
            loadAISecurity();
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

// ---------------------------------------------------------------------------
// AI Security Monitor
// ---------------------------------------------------------------------------
const SEVERITY_ICONS = {
    critical: 'fa-radiation',
    high: 'fa-exclamation-triangle',
    medium: 'fa-exclamation-circle',
    low: 'fa-info-circle',
    info: 'fa-check-circle'
};

function riskBadge(level) {
    const lvl = String(level || 'LOW').toLowerCase();
    return `<span class="risk-badge ${lvl}">${escapeHtml(String(level || 'LOW'))}</span>`;
}

function formatEventType(type) {
    return String(type || '').replace(/_/g, ' ');
}

// Load AI Security dashboard
async function loadAISecurity() {
    try {
        const response = await fetch(`${API_BASE}/api/ai_security/status`, {
            credentials: 'include'
        });
        if (response.status === 401) {
            return;
        }
        const data = await response.json();
        if (data.success && data.dashboard) {
            displayAISecurity(data.dashboard);
        } else {
            console.error('Failed to load AI security status:', data.error);
        }
    } catch (error) {
        console.error('Error loading AI security status:', error);
    }
}

// Display AI Security dashboard
function displayAISecurity(dashboard) {
    const threat = dashboard.threat_level || {};
    const levelBox = document.getElementById('aiThreatLevel');
    const level = String(threat.level || 'NORMAL').toLowerCase();
    levelBox.className = `ai-threat-level ${level}`;
    document.getElementById('aiThreatLevelText').textContent = `Threat level: ${threat.level || 'NORMAL'}`;
    document.getElementById('aiThreatLevelLabel').textContent = threat.label || '';
    
    const clientBox = document.getElementById('aiClientStatus');
    const client = dashboard.client || {};
    const action = client.action || 'allow';
    clientBox.innerHTML = `Your client: <span class="risk-badge ${action === 'allow' ? 'low' : (action === 'block' ? 'critical' : 'medium')}">${escapeHtml(action)}</span> score ${Number(client.score || 0).toFixed(0)}`;
    
    const stats = dashboard.stats || {};
    document.getElementById('aiStatAnalyzed').textContent = stats.expenses_analyzed || 0;
    document.getElementById('aiStatFlagged').textContent = stats.anomalies_flagged || 0;
    document.getElementById('aiStatBlocked').textContent = stats.threats_blocked || 0;
    document.getElementById('aiStatClients').textContent = stats.clients_blocked || 0;
    
    // Models
    const models = dashboard.models || {};
    const tc = models.threat_classifier || {};
    const ad = models.anomaly_detector || {};
    const id = models.intrusion_detector || {};
    const llm = models.llm_analyst || {};
    document.getElementById('aiModels').innerHTML = `
        <div class="ai-model">
            <strong><i class="fas fa-bug"></i> Threat classifier</strong>
            <p>${escapeHtml(tc.model || '')}</p>
            <small>${tc.training_samples || 0} training samples · ${tc.vocabulary_size || 0} features · ${tc.signature_rules || 0} signature rules</small>
        </div>
        <div class="ai-model">
            <strong><i class="fas fa-chart-line"></i> Anomaly detector</strong>
            <p>${escapeHtml(ad.model || '')}</p>
            <small>${ad.entries_learned || 0} entries learned · ${ad.users_profiled || 0} users profiled · group mean $${Number(ad.group_mean_amount || 0).toFixed(2)}</small>
        </div>
        <div class="ai-model">
            <strong><i class="fas fa-user-shield"></i> Intrusion detector</strong>
            <p>${escapeHtml(id.model || '')}</p>
            <small>${id.clients_tracked || 0} clients tracked · ${id.currently_blocked || 0} blocked · thresholds ${id.thresholds ? `${id.thresholds.challenge}/${id.thresholds.throttle}/${id.thresholds.block}` : ''}</small>
        </div>
        <div class="ai-model">
            <strong><i class="fas fa-robot"></i> LLM analyst</strong>
            <p>${llm.available ? `Available (${escapeHtml(llm.model || '')})` : 'Not configured - rule-based explanations in use'}</p>
            <small>${llm.available ? `${llm.calls || 0} calls` : 'Set ANTHROPIC_API_KEY to enable Claude-backed incident explanations'}</small>
        </div>
    `;
    
    // Baselines
    const profiles = dashboard.user_profiles || {};
    const profileRows = Object.entries(profiles);
    document.getElementById('aiProfiles').innerHTML = profileRows.length === 0
        ? '<p class="loading-text">No baselines learned yet - add a few expenses</p>'
        : profileRows.map(([user, p]) => `
            <div class="ai-profile">
                <span class="ai-profile-user"><i class="fas fa-user"></i> ${escapeHtml(user)}</span>
                <span>${p.samples} entries · mean $${Number(p.mean_amount).toFixed(2)} ± $${Number(p.std_amount).toFixed(2)} · max $${Number(p.max_amount).toFixed(2)}</span>
            </div>
        `).join('');
    
    // Events
    const events = dashboard.recent_events || [];
    document.getElementById('aiEvents').innerHTML = events.length === 0
        ? '<div class="empty-state"><i class="fas fa-shield-alt"></i><p>No security events recorded</p></div>'
        : events.map(ev => {
            const severity = String(ev.severity || 'info').toLowerCase();
            const details = ev.details || {};
            const reasons = (details.reasons || []).slice(0, 2).map(escapeHtml).join('<br>');
            const when = ev.timestamp ? new Date(ev.timestamp + 'Z').toLocaleString() : '';
            return `
                <div class="ai-event ${severity}" data-event-id="${ev.id}">
                    <div class="ai-event-header">
                        <span><i class="fas ${SEVERITY_ICONS[severity] || 'fa-info-circle'}"></i> ${escapeHtml(formatEventType(ev.event_type))}</span>
                        <span class="risk-badge ${severity === 'critical' ? 'critical' : (severity === 'high' ? 'high' : (severity === 'medium' ? 'medium' : 'low'))}">${escapeHtml(severity)}</span>
                    </div>
                    <div class="ai-event-meta">
                        ${ev.user_id ? `user <strong>${escapeHtml(ev.user_id)}</strong> · ` : ''}client ${escapeHtml(ev.client_id || '')} · risk ${Number(ev.risk_score || 0).toFixed(0)} · ${escapeHtml(when)}
                    </div>
                    ${reasons ? `<div class="ai-event-reasons">${reasons}</div>` : ''}
                    ${details.description !== undefined ? `<div class="ai-event-payload">payload: <code>${escapeHtml(String(details.description))}</code></div>` : ''}
                    <button class="btn btn-secondary ai-explain-btn" onclick="explainEvent(${Number(ev.id)}, this)">
                        <i class="fas fa-comment-dots"></i> Explain
                    </button>
                    <div class="ai-explain"></div>
                </div>
            `;
        }).join('');
}

// Ask the engine (Claude when configured) to explain an event
async function explainEvent(eventId, button) {
    const container = button.parentElement.querySelector('.ai-explain');
    container.innerHTML = '<div class="loading-spinner"><i class="fas fa-spinner fa-spin"></i><p>Analysing...</p></div>';
    try {
        const response = await fetch(`${API_BASE}/api/ai_security/explain/${eventId}`, {
            credentials: 'include'
        });
        const data = await response.json();
        if (!data.success) {
            container.innerHTML = `<div class="ai-explain-body">Error: ${escapeHtml(data.error || 'unknown')}</div>`;
            return;
        }
        const ex = data.explanation || {};
        container.innerHTML = `
            <div class="ai-explain-body">
                <div class="ai-explain-source">${data.source === 'llm' ? '<i class="fas fa-robot"></i> Claude analyst' : '<i class="fas fa-cogs"></i> Rule-based analyst'} · likely attack: <strong>${ex.likely_attack ? 'yes' : 'no'}</strong> · severity ${riskBadge(ex.severity)}</div>
                <p>${escapeHtml(ex.summary || '')}</p>
                ${(ex.indicators || []).length ? `<strong>Indicators</strong><ul>${ex.indicators.map(i => `<li>${escapeHtml(i)}</li>`).join('')}</ul>` : ''}
                ${(ex.recommended_actions || []).length ? `<strong>Recommended actions</strong><ul>${ex.recommended_actions.map(i => `<li>${escapeHtml(i)}</li>`).join('')}</ul>` : ''}
            </div>
        `;
    } catch (error) {
        container.innerHTML = `<div class="ai-explain-body">Error: ${escapeHtml(error.message)}</div>`;
    }
}

// Dry-run analysis of an expense / payload
async function runAITest() {
    const payer = document.getElementById('aiTestPayer').value.trim() || currentUser;
    const amount = parseFloat(document.getElementById('aiTestAmount').value) || 0;
    const description = document.getElementById('aiTestDescription').value.trim();
    const resultDiv = document.getElementById('aiTestResult');
    if (!description) {
        showToast('Enter a description or payload to analyse', 'error');
        return;
    }
    resultDiv.className = 'ai-test-result show';
    resultDiv.innerHTML = '<div class="loading-spinner"><i class="fas fa-spinner fa-spin"></i><p>Analysing...</p></div>';
    try {
        const response = await fetch(`${API_BASE}/api/ai_security/analyze`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ payer, amount, description })
        });
        const data = await response.json();
        if (!data.success) {
            resultDiv.innerHTML = `<div class="ai-test-verdict block">Error: ${escapeHtml(data.error || 'analysis failed')}</div>`;
            return;
        }
        const a = data.analysis;
        const threat = a.threat || {};
        const anomaly = a.anomaly || {};
        const verdictClass = a.action === 'block' ? 'block' : (a.action === 'flag' ? 'flag' : 'allow');
        const verdictIcon = a.action === 'block' ? 'fa-ban' : (a.action === 'flag' ? 'fa-flag' : 'fa-check-circle');
        resultDiv.innerHTML = `
            <div class="ai-test-verdict ${verdictClass}">
                <i class="fas ${verdictIcon}"></i>
                <div>
                    <strong>Verdict: ${escapeHtml(String(a.action).toUpperCase())}</strong> ${riskBadge(a.risk_level)} <span>risk score ${Number(a.risk_score).toFixed(0)}/100</span>
                    ${a.would_block ? `<p>${escapeHtml(a.block_reason || '')}</p>` : ''}
                </div>
            </div>
            <div class="ai-test-details">
                <div>
                    <strong>Threat classifier</strong>
                    <p>${escapeHtml(threat.description || threat.label || '')} · confidence ${(Number(threat.confidence || 0) * 100).toFixed(0)}%
                    ${threat.signatures && threat.signatures.length ? `<br><small>rules: ${threat.signatures.map(escapeHtml).join(', ')}</small>` : ''}</p>
                    <div class="ai-proba">
                        ${Object.entries(threat.probabilities || {}).map(([label, p]) => `
                            <div class="ai-proba-row"><span>${escapeHtml(label)}</span><div class="ai-proba-bar"><div style="width:${Math.max(1, p * 100).toFixed(1)}%"></div></div><span>${(p * 100).toFixed(0)}%</span></div>
                        `).join('')}
                    </div>
                </div>
                <div>
                    <strong>Anomaly detector</strong> ${riskBadge(anomaly.level)}
                    <p>score ${Number(anomaly.score || 0).toFixed(0)} · baseline: ${escapeHtml((anomaly.baseline || {}).source || 'none')}${anomaly.cold_start ? ' (cold start)' : ''}</p>
                    ${(anomaly.signals || []).length
                        ? `<ul>${anomaly.signals.map(sig => `<li><strong>${escapeHtml(sig.name)}</strong> (+${sig.score}): ${escapeHtml(sig.detail)}</li>`).join('')}</ul>`
                        : '<p class="loading-text">No behavioural anomalies</p>'}
                </div>
            </div>
        `;
    } catch (error) {
        resultDiv.innerHTML = `<div class="ai-test-verdict block">Error: ${escapeHtml(error.message)}</div>`;
    }
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

