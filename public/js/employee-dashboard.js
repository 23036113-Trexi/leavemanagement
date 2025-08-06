document.addEventListener('DOMContentLoaded', function() {
    // No need to get userId from URL anymore - using session-based authentication
    loadLeaveBalance();
    loadUpcomingLeaveRequests();
    
    // Load manager-specific data if user is a manager
    loadManagerDashboardData();
    
    setupRefreshButton();
    setupFilterControls();
    setupTableSorting();
});

// Load manager-specific dashboard data
async function loadManagerDashboardData() {
    // Check if the Team Management section exists (indicates user is manager or admin)
    const teamManagementSection = document.querySelector('.dashboard-section h3[contains="Team Management"]');
    const pendingCountElement = document.getElementById('pendingApprovalsCount');
    const teamCountElement = document.getElementById('teamMembersCount');
    
    // Alternative check: look for the pendingApprovalsCount element which only exists for managers
    if (pendingCountElement) {
        await loadPendingApprovalsCount();
    }
    
    // Load team members count if element exists
    if (teamCountElement) {
        await loadTeamMembersCount();
    }
    
    // Load admin-specific data if user is admin
    await loadAdminDashboardData();
}

// Load admin-specific dashboard data
async function loadAdminDashboardData() {
    const totalUsersCountElement = document.getElementById('totalUsersCount');
    const leaveTypesCountElement = document.getElementById('leaveTypesCount');
    
    // Load total users count if element exists (admin only)
    if (totalUsersCountElement) {
        await loadTotalUsersCount();
    }
    
    // Load leave types count if element exists (admin only)
    if (leaveTypesCountElement) {
        await loadLeaveTypesCount();
    }
}

function getUserIdFromURL() {
    const pathParts = window.location.pathname.split('/');
    const userIdIndex = pathParts.indexOf('dashboard') + 1;
    return pathParts[userIdIndex] ? parseInt(pathParts[userIdIndex]) : null;
}

async function loadLeaveBalance() {
    const loadingElement = document.getElementById('balance-loading');
    const contentElement = document.getElementById('balance-content');
    const errorElement = document.getElementById('balance-error');
    
    try {
        showLoading(loadingElement);
        
        const response = await fetch('/employee/leave-balance');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const response_data = await response.json();
        
        displayLeaveBalance(response_data.data);
        showContent(contentElement);
    } catch (error) {
        console.error('Error loading leave balance:', error);
        showError(errorElement, 'Failed to load leave balance. Please try again.');
    } finally {
        hideLoading(loadingElement);
    }
}

async function loadUpcomingLeaveRequests() {
    const loadingElement = document.getElementById('upcoming-loading');
    const contentElement = document.getElementById('upcoming-content');
    const errorElement = document.getElementById('upcoming-error');
    const statusFilter = document.getElementById('statusFilter');
    
    try {
        showLoading(loadingElement);
        
        // Build URL with status filter if selected
        let url = '/employee/leave-requests';
        if (statusFilter && statusFilter.value) {
            url += `?status=${encodeURIComponent(statusFilter.value)}`;
        }
        
        const response = await fetch(url);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const response_data = await response.json();
        
        // Store the request data for modal access
        currentEmployeeRequests = response_data.data.upcoming_requests;
        displayUpcomingRequests(response_data.data.upcoming_requests);
        showContent(contentElement);
    } catch (error) {
        console.error('Error loading upcoming requests:', error);
        showError(errorElement, 'Failed to load upcoming requests. Please try again.');
    } finally {
        hideLoading(loadingElement);
    }
}


function displayLeaveBalance(balanceData) {
    // Update Annual Leave
    const annualCurrent = document.querySelector('[data-balance-type="annual"]');
    const annualUsed = document.querySelector('[data-used-type="annual"]');
    const annualTotal = document.querySelector('[data-total-type="annual"]');
    const annualProgress = document.querySelector('[data-progress-type="annual"]');
    
    const annualBalance = balanceData.annual_leave_balance || 0;
    const annualEntitlement = balanceData.annual_leave_entitlement || 10;
    const annualUsedDays = Math.max(0, annualEntitlement - annualBalance);
    
    if (annualCurrent) {
        annualCurrent.textContent = annualBalance;
    }
    if (annualUsed) {
        annualUsed.textContent = annualUsedDays;
    }
    if (annualTotal) {
        annualTotal.textContent = annualEntitlement;
    }
    if (annualProgress) {
        const percentage = (annualBalance / annualEntitlement) * 100;
        annualProgress.style.width = `${Math.max(0, Math.min(100, percentage))}%`;
    }
    
    // Update Medical Leave
    const medicalCurrent = document.querySelector('[data-balance-type="medical"]');
    const medicalUsed = document.querySelector('[data-used-type="medical"]');
    const medicalTotal = document.querySelector('[data-total-type="medical"]');
    const medicalProgress = document.querySelector('[data-progress-type="medical"]');
    
    const medicalBalance = balanceData.medical_leave_balance || 0;
    const medicalEntitlement = balanceData.medical_leave_entitlement || 14;
    const medicalUsedDays = Math.max(0, medicalEntitlement - medicalBalance);
    
    if (medicalCurrent) {
        medicalCurrent.textContent = medicalBalance;
    }
    if (medicalUsed) {
        medicalUsed.textContent = medicalUsedDays;
    }
    if (medicalTotal) {
        medicalTotal.textContent = medicalEntitlement;
    }
    if (medicalProgress) {
        const percentage = (medicalBalance / medicalEntitlement) * 100;
        medicalProgress.style.width = `${Math.max(0, Math.min(100, percentage))}%`;
    }
    
    // Update Other Leave
    const otherCurrent = document.querySelector('[data-balance-type="other"]');
    const otherUsed = document.querySelector('[data-used-type="other"]');
    const otherTotal = document.querySelector('[data-total-type="other"]');
    const otherProgress = document.querySelector('[data-progress-type="other"]');
    
    const otherBalance = balanceData.other_leave_balance || 0;
    const otherEntitlement = balanceData.other_leave_entitlement || 5;
    const otherUsedDays = Math.max(0, otherEntitlement - otherBalance);
    
    if (otherCurrent) {
        otherCurrent.textContent = otherBalance;
    }
    if (otherUsed) {
        otherUsed.textContent = otherUsedDays;
    }
    if (otherTotal) {
        otherTotal.textContent = otherEntitlement;
    }
    if (otherProgress) {
        const percentage = (otherBalance / otherEntitlement) * 100;
        otherProgress.style.width = `${Math.max(0, Math.min(100, percentage))}%`;
    }
}

function updateProgressBar(progressId, currentValue, maxValue) {
    const progressBar = document.getElementById(progressId);
    if (progressBar) {
        const percentage = (currentValue / maxValue) * 100;
        progressBar.style.width = `${Math.min(percentage, 100)}%`;
        
        if (percentage < 25) {
            progressBar.className = 'progress-bar progress-bar-danger';
        } else if (percentage < 50) {
            progressBar.className = 'progress-bar progress-bar-warning';
        } else {
            progressBar.className = 'progress-bar progress-bar-success';
        }
    }
}

function displayUpcomingRequests(requests) {
    const tableBody = document.getElementById('upcomingRequestsBody');
    const loadingSpinner = document.getElementById('requestsLoadingSpinner');
    const noRequestsMessage = document.getElementById('noRequestsMessage');
    
    // Debug logging
    console.log('Employee requests data:', requests);
    
    // Hide loading spinner
    if (loadingSpinner) {
        loadingSpinner.style.display = 'none';
    }
    
    if (!requests || requests.length === 0) {
        // Show no requests message
        if (noRequestsMessage) {
            noRequestsMessage.style.display = 'flex';
        }
        // Keep the no-data row but hide loading
        tableBody.innerHTML = `
            <tr class="no-data-row">
                <td colspan="7" class="no-data">
                    <div class="no-requests-message" style="display: flex;">
                        <span class="no-data-icon">📅</span>
                        <span>No upcoming leave requests found</span>
                    </div>
                </td>
            </tr>
        `;
        return;
    }
    
    // Hide no requests message and populate table
    if (noRequestsMessage) {
        noRequestsMessage.style.display = 'none';
    }
    
    tableBody.innerHTML = requests.map(request => `
        <tr data-request-id="${request.id}">
            <td>
                <span class="leave-type ${getLeaveTypeClass(request.leave_type)}">${request.leave_type}</span>
            </td>
            <td data-sort="${request.start_date}">
                <div class="date-info">
                    <span class="date-value">${formatDateWithDay(request.start_date)}</span>
                    <small class="date-relative">${getRelativeDate(request.start_date)}</small>
                </div>
            </td>
            <td data-sort="${request.end_date}">
                <div class="date-info">
                    <span class="date-value">${formatDateWithDay(request.end_date)}</span>
                    <small class="date-relative">${getRelativeDate(request.end_date)}</small>
                </div>
            </td>
            <td data-sort="${request.number_of_days}">
                <div class="duration-info">
                    <span class="duration-value">${formatDuration(request.number_of_days)}</span>
                    ${request.half_day ? `<small class="half-day-indicator">${request.half_day} Half Day</small>` : ''}
                </div>
            </td>
            <td>
                <span class="status-badge ${getStatusClass(request.approval_status)}" data-status="${request.approval_status || 'pending'}">${getStatusText(request.approval_status)}</span>
            </td>
            <td>
                <div class="document-cell">
                    ${request.image ? 
                        `<a href="/uploads/${request.image}" target="_blank" class="document-link" title="View uploaded document">
                            <span class="document-icon">📎</span>
                            View Document
                        </a>` : 
                        `<span class="no-document">No document</span>`
                    }
                </div>
            </td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-info btn-xs" onclick="viewRequestDetails(${request.id})" title="View Details">
                        <span>👁️</span>
                        View
                    </button>
                    ${(!request.approval_status || request.approval_status === 'pending') ? 
                        `<button class="btn btn-warning btn-xs" onclick="cancelRequest(${request.id})" title="Cancel Request">
                            <span>❌</span>
                            Cancel
                        </button>` : ''}
                </div>
            </td>
        </tr>
    `).join('');
}

function getLeaveTypeClass(leaveType) {
    if (!leaveType) return '';
    if (leaveType.toLowerCase().includes('annual')) return 'annual';
    if (leaveType.toLowerCase().includes('medical')) return 'medical';
    return 'other';
}

function getStatusClass(status) {
    switch (status) {
        case 'approved': return 'approved';
        case 'rejected': return 'rejected';
        default: return 'pending';
    }
}

function getStatusText(status) {
    switch (status) {
        case 'approved': return 'Approved';
        case 'rejected': return 'Rejected';
        default: return 'Pending';
    }
}


function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function formatDateWithDay(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        weekday: 'short',
        month: 'short',
        day: 'numeric',
        year: 'numeric'
    });
}

function getRelativeDate(dateString) {
    if (!dateString) return '';
    const date = new Date(dateString);
    const today = new Date();
    const diffTime = date - today;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Tomorrow';
    if (diffDays === -1) return 'Yesterday';
    if (diffDays > 1 && diffDays <= 7) return `In ${diffDays} days`;
    if (diffDays < -1 && diffDays >= -7) return `${Math.abs(diffDays)} days ago`;
    if (diffDays > 7) return `In ${Math.ceil(diffDays / 7)} weeks`;
    if (diffDays < -7) return `${Math.ceil(Math.abs(diffDays) / 7)} weeks ago`;
    
    return '';
}

function formatDuration(days) {
    if (!days) return '0 days';
    const numDays = parseFloat(days);
    
    if (numDays === 0.5) return '½ day';
    if (numDays === 1) return '1 day';
    if (numDays % 1 === 0.5) return `${Math.floor(numDays)}½ days`;
    
    return `${numDays} ${numDays === 1 ? 'day' : 'days'}`;
}

function viewRequestDetails(requestId) {
    // Find the request data from stored API response
    const request = currentEmployeeRequests.find(r => r.id === requestId);
    if (!request) {
        console.error('Request data not found');
        return;
    }
    
    showRequestDetailsModal(request);
}

function showRequestDetailsModal(request) {
    const modal = document.getElementById('requestDetailsModal');
    const modalBody = document.getElementById('modalBody');
    
    if (!modal || !modalBody) {
        console.error('Modal elements not found');
        return;
    }
    
    // Display manager comment if request is rejected or approved and has a comment
    const managerComment = request.approval_comment && (request.approval_status === 'rejected' || request.approval_status === 'approved') ? `
        <div class="detail-row">
            <label>Manager's Comment:</label>
            <span class="manager-comment">${request.approval_comment}</span>
        </div>
    ` : '';
    
    modalBody.innerHTML = `
        <div class="request-details">
            <div class="detail-row">
                <label>Leave Type:</label>
                <span class="leave-type ${getLeaveTypeClass(request.leave_type)}">${request.leave_type}</span>
            </div>
            <div class="detail-row">
                <label>Start Date:</label>
                <span>${formatDateWithDay(request.start_date)}</span>
            </div>
            <div class="detail-row">
                <label>End Date:</label>
                <span>${formatDateWithDay(request.end_date)}</span>
            </div>
            <div class="detail-row">
                <label>Duration:</label>
                <span>${formatDuration(request.number_of_days)}${request.half_day ? ` (${request.half_day} Half Day)` : ''}</span>
            </div>
            <div class="detail-row">
                <label>Status:</label>
                <span class="status-badge ${getStatusClass(request.approval_status)}">${getStatusText(request.approval_status)}</span>
            </div>
            ${request.reason ? `
            <div class="detail-row">
                <label>Reason:</label>
                <span class="request-reason">${request.reason}</span>
            </div>
            ` : ''}
            <div class="detail-row">
                <label>Request Date:</label>
                <span>${formatDateWithDay(request.request_date)}</span>
            </div>
            ${request.image ? `
            <div class="detail-row">
                <label>Supporting Document:</label>
                <a href="/uploads/${request.image}" target="_blank" class="document-link">
                    <span class="document-icon">📎</span>
                    View Document
                </a>
            </div>
            ` : ''}
            ${managerComment}
        </div>
        <div class="modal-actions">
            ${(!request.approval_status || request.approval_status === 'pending') ? 
                `<button class="btn btn-warning btn-sm" onclick="cancelRequest(${request.id}); closeModal();">
                    Cancel Request
                </button>` : ''}
            <button class="btn btn-secondary btn-sm" onclick="closeModal();">Close</button>
        </div>
    `;
    
    modal.style.display = 'flex';
}

function closeModal() {
    const modal = document.getElementById('requestDetailsModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Setup modal close handlers
document.addEventListener('DOMContentLoaded', function() {
    const closeModalBtn = document.getElementById('closeModal');
    const modal = document.getElementById('requestDetailsModal');
    
    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', closeModal);
    }
    
    if (modal) {
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                closeModal();
            }
        });
    }
    
    // ESC key to close modal
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeModal();
        }
    });
});

async function cancelRequest(requestId) {
    if (!confirm('Are you sure you want to cancel this leave request?')) {
        return;
    }
    
    try {
        const response = await fetch(`/leave-request/${requestId}/cancel`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.message || `HTTP error! status: ${response.status}`);
        }
        
        // Show success message
        alert('Leave request cancelled successfully!');
        
        // Refresh both leave balance and requests
        loadLeaveBalance();
        loadUpcomingLeaveRequests();
        
        // Close modal if it's open
        closeModal();
        
    } catch (error) {
        console.error('Error cancelling request:', error);
        alert(`Failed to cancel leave request: ${error.message}`);
    }
}

function setupRefreshButton() {
    const refreshBtn = document.getElementById('refreshRequests');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            loadUpcomingLeaveRequests();
        });
    }
}

function refreshDashboard() {
    loadLeaveBalance();
    loadUpcomingLeaveRequests();
}

function setupFilterControls() {
    const statusFilter = document.getElementById('statusFilter');
    
    // Only add this event listener if we're not in the user management modal
    // The user management modal has its own onchange="handleFilterChange()" handler
    if (statusFilter && !statusFilter.closest('.admin-modal')) {
        statusFilter.addEventListener('change', function() {
            loadUpcomingLeaveRequests();
        });
    }
}

function setupTableSorting() {
    const table = document.getElementById('upcomingRequestsTable');
    if (!table) return;
    
    const headers = table.querySelectorAll('th.sortable');
    let currentSort = { column: null, direction: 'asc' };
    
    headers.forEach(header => {
        header.addEventListener('click', function() {
            const column = this.dataset.column;
            
            // Reset all headers
            headers.forEach(h => {
                h.classList.remove('sort-asc', 'sort-desc');
            });
            
            // Determine sort direction
            if (currentSort.column === column) {
                currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
            } else {
                currentSort.direction = 'asc';
            }
            currentSort.column = column;
            
            // Update header classes
            this.classList.add(currentSort.direction === 'asc' ? 'sort-asc' : 'sort-desc');
            
            // Sort the table
            sortTable(column, currentSort.direction);
        });
    });
}

function sortTable(column, direction) {
    const tbody = document.getElementById('upcomingRequestsBody');
    const rows = Array.from(tbody.querySelectorAll('tr:not(.no-data-row)'));
    
    if (rows.length === 0) return;
    
    rows.sort((a, b) => {
        let aValue, bValue;
        
        switch (column) {
            case 'leave_type':
                aValue = a.querySelector('.leave-type')?.textContent.trim() || '';
                bValue = b.querySelector('.leave-type')?.textContent.trim() || '';
                break;
            case 'start_date':
            case 'end_date':
                aValue = a.querySelector(`[data-sort]`)?.dataset.sort || '';
                bValue = b.querySelector(`[data-sort]`)?.dataset.sort || '';
                aValue = new Date(aValue);
                bValue = new Date(bValue);
                break;
            case 'days':
                aValue = parseFloat(a.querySelector('[data-sort]')?.dataset.sort || '0');
                bValue = parseFloat(b.querySelector('[data-sort]')?.dataset.sort || '0');
                break;
            case 'status':
                aValue = a.querySelector('.status-badge')?.textContent.trim() || '';
                bValue = b.querySelector('.status-badge')?.textContent.trim() || '';
                break;
            default:
                return 0;
        }
        
        // Handle different data types
        if (aValue instanceof Date && bValue instanceof Date) {
            return direction === 'asc' ? aValue - bValue : bValue - aValue;
        } else if (typeof aValue === 'number' && typeof bValue === 'number') {
            return direction === 'asc' ? aValue - bValue : bValue - aValue;
        } else {
            // String comparison
            aValue = String(aValue).toLowerCase();
            bValue = String(bValue).toLowerCase();
            if (direction === 'asc') {
                return aValue.localeCompare(bValue);
            } else {
                return bValue.localeCompare(aValue);
            }
        }
    });
    
    // Reorder rows in the table
    rows.forEach(row => tbody.appendChild(row));
}



function showLoading(element) {
    if (element) element.style.display = 'block';
}

function hideLoading(element) {
    if (element) element.style.display = 'none';
}

function showContent(element) {
    if (element) element.style.display = 'block';
}

function showError(element, message) {
    if (element) {
        element.textContent = message;
        element.style.display = 'block';
    }
}


window.addEventListener('beforeunload', function() {
    const refreshBtn = document.getElementById('refresh-dashboard');
    if (refreshBtn) {
        refreshBtn.removeEventListener('click', refreshDashboard);
    }
});

// Role-Based Section Functions

// Manager-specific global variables
let currentManagerRequests = [];
let currentRequestFilters = {
    status: '',
    employee_id: '',
    leave_type: '',
    start_date: '',
    end_date: '',
    page: 1,
    limit: 10
};

// Employee request data storage
let currentEmployeeRequests = [];

// Team Management Functions (Manager and Admin)
async function loadPendingApprovalsCount() {
    try {
        const response = await fetch('/manager/pending-count');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const responseData = await response.json();
        const pendingCount = responseData.data.pending_count;
        
        // Update the count in the UI
        const countElement = document.getElementById('pendingApprovalsCount');
        if (countElement) {
            countElement.textContent = pendingCount;
        }
        
    } catch (error) {
        console.error('Error loading pending approvals count:', error);
        // If there's an error, show 0 instead of --
        const countElement = document.getElementById('pendingApprovalsCount');
        if (countElement) {
            countElement.textContent = '0';
        }
    }
}

async function loadTeamMembersCount() {
    try {
        const response = await fetch('/manager/team-count');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const responseData = await response.json();
        const teamCount = responseData.data.team_count;
        
        // Update the count in the UI
        const countElement = document.getElementById('teamMembersCount');
        if (countElement) {
            countElement.textContent = teamCount;
        }
        
    } catch (error) {
        console.error('Error loading team members count:', error);
        // If there's an error, show 0 instead of --
        const countElement = document.getElementById('teamMembersCount');
        if (countElement) {
            countElement.textContent = '0';
        }
    }
}

async function loadTotalUsersCount() {
    try {
        const response = await fetch('/admin/users');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const responseData = await response.json();
        const totalCount = responseData.count;
        
        // Update the count in the UI
        const countElement = document.getElementById('totalUsersCount');
        if (countElement) {
            countElement.textContent = totalCount;
        }
        
    } catch (error) {
        console.error('Error loading total users count:', error);
        // If there's an error, show 0 instead of --
        const countElement = document.getElementById('totalUsersCount');
        if (countElement) {
            countElement.textContent = '0';
        }
    }
}

async function loadLeaveTypesCount() {
    try {
        const response = await fetch('/leave-types');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const responseData = await response.json();
        const leaveTypesCount = responseData.data.length;
        
        // Update the count in the UI
        const countElement = document.getElementById('leaveTypesCount');
        if (countElement) {
            countElement.textContent = leaveTypesCount;
        }
        
    } catch (error) {
        console.error('Error loading leave types count:', error);
        // If there's an error, show 0 instead of --
        const countElement = document.getElementById('leaveTypesCount');
        if (countElement) {
            countElement.textContent = '0';
        }
    }
}

async function loadTeamMembers() {
    try {
        const response = await fetch('/manager/team-members');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const responseData = await response.json();
        const teamMembers = responseData.data.team_members;
        
        // Populate the employee filter dropdown
        const employeeFilter = document.getElementById('managerEmployeeFilter');
        if (employeeFilter) {
            // Clear existing options except the default "All Employees"
            employeeFilter.innerHTML = '<option value="">All Employees</option>';
            
            // Add each team member as an option
            teamMembers.forEach(member => {
                const option = document.createElement('option');
                option.value = member.id;
                // Display name with email for disambiguation (e.g., "John Smith (john.smith@company.com)")
                option.textContent = member.name ? `${member.name} (${member.email})` : member.email;
                employeeFilter.appendChild(option);
            });
        }
        
    } catch (error) {
        console.error('Error loading team members:', error);
        // Don't show error to user, just log it - dropdown will remain with default option
    }
}

async function viewPendingApprovals() {
    try {
        await loadManagerRequests('pending');
        showManagerSection();
    } catch (error) {
        console.error('Error loading pending approvals:', error);
        alert('Failed to load pending approvals. Please try again.');
    }
}

async function viewTeamCalendar() {
    try {
        await loadManagerRequests();
        showManagerSection();
    } catch (error) {
        console.error('Error loading team requests:', error);
        alert('Failed to load team calendar. Please try again.');
    }
}


// Manager Request Management Functions
async function loadManagerRequests(statusFilter = '') {
    const loadingElement = document.getElementById('manager-requests-loading');
    const contentElement = document.getElementById('manager-requests-content');
    const errorElement = document.getElementById('manager-requests-error');
    const exportButton = document.getElementById('exportToExcel');
    
    try {
        showLoading(loadingElement);
        
        // Disable export button while loading
        if (exportButton) {
            exportButton.disabled = true;
            exportButton.title = 'Loading data...';
            exportButton.classList.add('disabled');
        }
        
        // Build query parameters
        const params = new URLSearchParams();
        
        // Use the statusFilter parameter if provided, otherwise use the filter from dropdown
        const effectiveStatusFilter = statusFilter || currentRequestFilters.status;
        
        if (effectiveStatusFilter) params.append('status', effectiveStatusFilter);
        if (currentRequestFilters.employee_id) params.append('employee_id', currentRequestFilters.employee_id);
        if (currentRequestFilters.leave_type) params.append('leave_type', currentRequestFilters.leave_type);
        if (currentRequestFilters.start_date) params.append('start_date', currentRequestFilters.start_date);
        if (currentRequestFilters.end_date) params.append('end_date', currentRequestFilters.end_date);
        params.append('page', currentRequestFilters.page);
        params.append('limit', currentRequestFilters.limit);
        
        const url = effectiveStatusFilter === 'pending' 
            ? '/manager/pending-requests'
            : `/manager/team-requests?${params.toString()}`;
        
        const response = await fetch(url);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const responseData = await response.json();
        
        if (effectiveStatusFilter === 'pending') {
            currentManagerRequests = responseData.data.pending_requests;
            displayManagerRequests(currentManagerRequests);
        } else {
            currentManagerRequests = responseData.data.team_requests;
            displayManagerRequests(currentManagerRequests, responseData.data.pagination);
        }
        
        showContent(contentElement);
    } catch (error) {
        console.error('Error loading manager requests:', error);
        showError(errorElement, 'Failed to load team requests. Please try again.');
        
        // Keep export button disabled on error
        if (exportButton) {
            exportButton.disabled = true;
            exportButton.title = 'Error loading data - cannot export';
            exportButton.classList.add('disabled');
        }
    } finally {
        hideLoading(loadingElement);
    }
}

function displayManagerRequests(requests, pagination = null) {
    const tableBody = document.getElementById('managerRequestsBody');
    const paginationContainer = document.getElementById('managerPagination');
    const exportButton = document.getElementById('exportToExcel');
    
    // Debug logging
    console.log('Manager requests data:', requests);
    
    if (!requests || requests.length === 0) {
        tableBody.innerHTML = `
            <tr class="no-data-row">
                <td colspan="9" class="no-data">
                    <div class="no-requests-message">
                        <span class="no-data-icon">📋</span>
                        <span>No leave requests found</span>
                    </div>
                </td>
            </tr>
        `;
        if (paginationContainer) paginationContainer.innerHTML = '';
        
        // Disable export button when no data
        if (exportButton) {
            exportButton.disabled = true;
            exportButton.title = 'No data available to export';
            exportButton.classList.add('disabled');
        }
        return;
    }
    
    // Enable export button when data is available
    if (exportButton) {
        exportButton.disabled = false;
        exportButton.title = 'Export filtered data to Excel';
        exportButton.classList.remove('disabled');
    }
    
    tableBody.innerHTML = requests.map(request => `
        <tr data-request-id="${request.id}" class="manager-request-row">
            <td>
                <div class="employee-info">
                    <span class="employee-name">${request.employee_name || request.employee_email}</span>
                </div>
            </td>
            <td>
                <span class="leave-type ${getLeaveTypeClass(request.leave_type)}">${request.leave_type}</span>
            </td>
            <td data-sort="${request.start_date}">
                <div class="date-info">
                    <span class="date-value">${formatDateWithDay(request.start_date)}</span>
                    <small class="date-relative">${getRelativeDate(request.start_date)}</small>
                </div>
            </td>
            <td data-sort="${request.end_date}">
                <div class="date-info">
                    <span class="date-value">${formatDateWithDay(request.end_date)}</span>
                    <small class="date-relative">${getRelativeDate(request.end_date)}</small>
                </div>
            </td>
            <td data-sort="${request.number_of_days}">
                <div class="duration-info">
                    <span class="duration-value">${formatDuration(request.number_of_days)}</span>
                    ${request.half_day ? `<small class="half-day-indicator">${request.half_day} Half Day</small>` : ''}
                </div>
            </td>
            <td>
                <span class="status-badge ${getStatusClass(request.approval_status)}" data-status="${request.approval_status || 'pending'}">${getStatusText(request.approval_status)}</span>
            </td>
            <td>
                <div class="reason-preview" title="${request.reason || 'No reason provided'}">
                    ${(request.reason || 'No reason provided').substring(0, 50)}${(request.reason || '').length > 50 ? '...' : ''}
                </div>
            </td>
            <td>
                <div class="document-cell">
                    ${request.image ? 
                        `<a href="/uploads/${request.image}" target="_blank" class="document-link" title="View uploaded document">
                            <span class="document-icon">📎</span>
                            View Document
                        </a>` : 
                        `<span class="no-document">No document</span>`
                    }
                </div>
            </td>
            <td>
                <div class="btn-group manager-actions">
                    <button class="btn btn-info btn-xs" onclick="viewManagerRequestDetails(${request.id})" title="View Details">
                        <span>👁️</span>
                        View
                    </button>
                    ${request.approval_status === 'pending' || !request.approval_status ? 
                        `<button class="btn btn-success btn-xs" onclick="showApprovalModal(${request.id})" title="Approve Request">
                            <span>✅</span>
                            Approve
                        </button>
                        <button class="btn btn-danger btn-xs" onclick="showRejectionModal(${request.id})" title="Reject Request">
                            <span>❌</span>
                            Reject
                        </button>` : ''}
                </div>
            </td>
        </tr>
    `).join('');
    
    // Display pagination if provided
    if (pagination && paginationContainer) {
        displayPagination(pagination, paginationContainer);
    }
}

function displayPagination(pagination, container) {
    if (pagination.total_pages <= 1) {
        container.innerHTML = '';
        return;
    }
    
    let paginationHtml = '<div class="pagination-container">';
    
    // Previous button
    if (pagination.has_previous_page) {
        paginationHtml += `<button class="btn btn-sm btn-secondary" onclick="changePage(${pagination.current_page - 1})">Previous</button>`;
    }
    
    // Page numbers
    const startPage = Math.max(1, pagination.current_page - 2);
    const endPage = Math.min(pagination.total_pages, pagination.current_page + 2);
    
    for (let i = startPage; i <= endPage; i++) {
        const activeClass = i === pagination.current_page ? 'btn-primary' : 'btn-secondary';
        paginationHtml += `<button class="btn btn-sm ${activeClass}" onclick="changePage(${i})">${i}</button>`;
    }
    
    // Next button
    if (pagination.has_next_page) {
        paginationHtml += `<button class="btn btn-sm btn-secondary" onclick="changePage(${pagination.current_page + 1})">Next</button>`;
    }
    
    paginationHtml += `<span class="pagination-info">Page ${pagination.current_page} of ${pagination.total_pages} (${pagination.total_records} total)</span>`;
    paginationHtml += '</div>';
    
    container.innerHTML = paginationHtml;
}

function changePage(page) {
    currentRequestFilters.page = page;
    loadManagerRequests();
}

function showManagerSection() {
    // Hide employee sections, show manager section
    const employeeSection = document.getElementById('employee-section');
    const managerSection = document.getElementById('manager-section');
    
    if (employeeSection) employeeSection.style.display = 'none';
    if (managerSection) managerSection.style.display = 'block';
    
    // Load team members for the employee filter dropdown
    loadTeamMembers();
}

function showEmployeeSection() {
    // Show employee sections, hide manager section
    const employeeSection = document.getElementById('employee-section');
    const managerSection = document.getElementById('manager-section');
    
    if (employeeSection) employeeSection.style.display = 'block';
    if (managerSection) managerSection.style.display = 'none';
}

function viewManagerRequestDetails(requestId) {
    const request = currentManagerRequests.find(r => r.id === requestId);
    if (!request) {
        console.error('Request not found');
        return;
    }
    
    showManagerRequestDetailsModal(request);
}

function showManagerRequestDetailsModal(request) {
    const modal = document.getElementById('managerRequestDetailsModal');
    const modalBody = document.getElementById('managerModalBody');
    
    if (!modal || !modalBody) {
        console.error('Manager modal elements not found');
        return;
    }
    
    const approvalComment = request.approval_comment ? `
        <div class="detail-row">
            <label>Manager Comment:</label>
            <span class="manager-comment">${request.approval_comment}</span>
        </div>
    ` : '';
    
    modalBody.innerHTML = `
        <div class="request-details">
            <div class="detail-row">
                <label>Employee:</label>
                <span class="employee-name">${request.employee_name || request.employee_email}</span>
            </div>
            <div class="detail-row">
                <label>Leave Type:</label>
                <span class="leave-type ${getLeaveTypeClass(request.leave_type)}">${request.leave_type}</span>
            </div>
            <div class="detail-row">
                <label>Start Date:</label>
                <span>${formatDateWithDay(request.start_date)}</span>
            </div>
            <div class="detail-row">
                <label>End Date:</label>
                <span>${formatDateWithDay(request.end_date)}</span>
            </div>
            <div class="detail-row">
                <label>Duration:</label>
                <span>${formatDuration(request.number_of_days)}${request.half_day ? ` (${request.half_day} Half Day)` : ''}</span>
            </div>
            <div class="detail-row">
                <label>Status:</label>
                <span class="status-badge ${getStatusClass(request.approval_status)}">${getStatusText(request.approval_status)}</span>
            </div>
            <div class="detail-row">
                <label>Reason:</label>
                <span class="request-reason">${request.reason || 'No reason provided'}</span>
            </div>
            <div class="detail-row">
                <label>Request Date:</label>
                <span>${formatDateWithDay(request.request_date)}</span>
            </div>
            ${request.image ? `
            <div class="detail-row">
                <label>Supporting Document:</label>
                <a href="/uploads/${request.image}" target="_blank" class="document-link">
                    <span class="document-icon">📎</span>
                    View Document
                </a>
            </div>
            ` : ''}
            ${approvalComment}
        </div>
        <div class="modal-actions">
            ${(request.approval_status === 'pending' || !request.approval_status) ? 
                `<button class="btn btn-success btn-sm" onclick="showApprovalModal(${request.id}); closeManagerModal();">
                    <span>✅</span> Approve Request
                </button>
                <button class="btn btn-danger btn-sm" onclick="showRejectionModal(${request.id}); closeManagerModal();">
                    <span>❌</span> Reject Request
                </button>` : ''}
            <button class="btn btn-secondary btn-sm" onclick="closeManagerModal();">Close</button>
        </div>
    `;
    
    modal.style.display = 'flex';
}

function closeManagerModal() {
    const modal = document.getElementById('managerRequestDetailsModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Approval Modal Functions
function showApprovalModal(requestId) {
    const request = currentManagerRequests.find(r => r.id === requestId);
    if (!request) {
        console.error('Request not found');
        return;
    }
    
    const modal = document.getElementById('approvalModal');
    const modalBody = document.getElementById('approvalModalBody');
    
    if (!modal || !modalBody) {
        console.error('Approval modal elements not found');
        return;
    }
    
    modalBody.innerHTML = `
        <div class="approval-form">
            <div class="request-summary">
                <h4>Approve Leave Request</h4>
                <p><strong>Employee:</strong> ${request.employee_name || request.employee_email}</p>
                <p><strong>Leave Type:</strong> ${request.leave_type}</p>
                <p><strong>Duration:</strong> ${formatDuration(request.number_of_days)} (${formatDateWithDay(request.start_date)} - ${formatDateWithDay(request.end_date)})</p>
            </div>
            <div class="form-group">
                <label for="approvalComment">Comment (Optional):</label>
                <textarea id="approvalComment" class="form-control" rows="3" placeholder="Add a comment for the approval (optional)"></textarea>
            </div>
            <div class="modal-actions">
                <button class="btn btn-success" onclick="approveRequest(${requestId})">
                    <span>✅</span> Confirm Approval
                </button>
                <button class="btn btn-secondary" onclick="closeApprovalModal()">Cancel</button>
            </div>
        </div>
    `;
    
    modal.style.display = 'flex';
}

function closeApprovalModal() {
    const modal = document.getElementById('approvalModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Rejection Modal Functions
function showRejectionModal(requestId) {
    const request = currentManagerRequests.find(r => r.id === requestId);
    if (!request) {
        console.error('Request not found');
        return;
    }
    
    const modal = document.getElementById('rejectionModal');
    const modalBody = document.getElementById('rejectionModalBody');
    
    if (!modal || !modalBody) {
        console.error('Rejection modal elements not found');
        return;
    }
    
    modalBody.innerHTML = `
        <div class="rejection-form">
            <div class="request-summary">
                <h4>Reject Leave Request</h4>
                <p><strong>Employee:</strong> ${request.employee_name || request.employee_email}</p>
                <p><strong>Leave Type:</strong> ${request.leave_type}</p>
                <p><strong>Duration:</strong> ${formatDuration(request.number_of_days)} (${formatDateWithDay(request.start_date)} - ${formatDateWithDay(request.end_date)})</p>
            </div>
            <div class="form-group">
                <label for="rejectionComment">Reason for Rejection (Required):</label>
                <textarea id="rejectionComment" class="form-control" rows="4" placeholder="Please provide a clear reason for rejecting this request (minimum 5 characters)" required></textarea>
                <small class="form-text text-muted">A detailed explanation helps the employee understand the decision.</small>
            </div>
            <div class="modal-actions">
                <button class="btn btn-danger" onclick="rejectRequest(${requestId})">
                    <span>❌</span> Confirm Rejection
                </button>
                <button class="btn btn-secondary" onclick="closeRejectionModal()">Cancel</button>
            </div>
        </div>
    `;
    
    modal.style.display = 'flex';
}

function closeRejectionModal() {
    const modal = document.getElementById('rejectionModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// AJAX Functions for Approval/Rejection
async function approveRequest(requestId) {
    const commentField = document.getElementById('approvalComment');
    const comment = commentField ? commentField.value.trim() : '';
    
    try {
        const response = await fetch(`/manager/approve-request/${requestId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ comment })
        });
        
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.message || `HTTP error! status: ${response.status}`);
        }
        
        // Show success message
        alert(`Leave request approved successfully!\n\nEmployee: ${result.data.employee_name || result.data.employee_email}\nDays Approved: ${result.data.number_of_days}\nRemaining Balance: ${result.data.remaining_balance}`);
        
        // Close modal and refresh requests
        closeApprovalModal();
        await loadManagerRequests();
        await loadPendingApprovalsCount(); // Refresh the count
        
    } catch (error) {
        console.error('Error approving request:', error);
        alert(`Failed to approve leave request: ${error.message}`);
    }
}

async function rejectRequest(requestId) {
    const commentField = document.getElementById('rejectionComment');
    const comment = commentField ? commentField.value.trim() : '';
    
    // Validate rejection comment
    if (!comment) {
        alert('Please provide a reason for rejection.');
        return;
    }
    
    if (comment.length < 5) {
        alert('Rejection reason must be at least 5 characters long.');
        return;
    }
    
    try {
        const response = await fetch(`/manager/reject-request/${requestId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ comment })
        });
        
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.message || `HTTP error! status: ${response.status}`);
        }
        
        // Show success message
        alert(`Leave request rejected successfully!\n\nEmployee: ${result.data.employee_name || result.data.employee_email}\nReason: ${result.data.rejection_comment}`);
        
        // Close modal and refresh requests
        closeRejectionModal();
        await loadManagerRequests();
        await loadPendingApprovalsCount(); // Refresh the count
        
    } catch (error) {
        console.error('Error rejecting request:', error);
        alert(`Failed to reject leave request: ${error.message}`);
    }
}

// Filter Functions
function setupManagerFilters() {
    const statusFilter = document.getElementById('managerStatusFilter');
    const employeeFilter = document.getElementById('managerEmployeeFilter');
    const leaveTypeFilter = document.getElementById('managerLeaveTypeFilter');
    const startDateFilter = document.getElementById('managerStartDate');
    const endDateFilter = document.getElementById('managerEndDate');
    const clearFiltersBtn = document.getElementById('clearManagerFilters');
    
    // Status filter
    if (statusFilter) {
        statusFilter.addEventListener('change', function() {
            currentRequestFilters.status = this.value;
            currentRequestFilters.page = 1;
            loadManagerRequests();
        });
    }
    
    // Employee filter
    if (employeeFilter) {
        employeeFilter.addEventListener('change', function() {
            currentRequestFilters.employee_id = this.value;
            currentRequestFilters.page = 1;
            loadManagerRequests();
        });
    }
    
    // Leave type filter
    if (leaveTypeFilter) {
        leaveTypeFilter.addEventListener('change', function() {
            currentRequestFilters.leave_type = this.value;
            currentRequestFilters.page = 1;
            loadManagerRequests();
        });
    }
    
    // Date filters
    if (startDateFilter) {
        startDateFilter.addEventListener('change', function() {
            currentRequestFilters.start_date = this.value;
            currentRequestFilters.page = 1;
            loadManagerRequests();
        });
    }
    
    if (endDateFilter) {
        endDateFilter.addEventListener('change', function() {
            currentRequestFilters.end_date = this.value;
            currentRequestFilters.page = 1;
            loadManagerRequests();
        });
    }
    
    // Clear filters
    if (clearFiltersBtn) {
        clearFiltersBtn.addEventListener('click', function() {
            clearAllManagerFilters();
        });
    }
}

function clearAllManagerFilters() {
    currentRequestFilters = {
        status: '',
        employee_id: '',
        leave_type: '',
        start_date: '',
        end_date: '',
        page: 1,
        limit: 10
    };
    
    // Clear form inputs
    const statusFilter = document.getElementById('managerStatusFilter');
    const employeeFilter = document.getElementById('managerEmployeeFilter');
    const leaveTypeFilter = document.getElementById('managerLeaveTypeFilter');
    const startDateFilter = document.getElementById('managerStartDate');
    const endDateFilter = document.getElementById('managerEndDate');
    
    if (statusFilter) statusFilter.value = '';
    if (employeeFilter) employeeFilter.value = '';
    if (leaveTypeFilter) leaveTypeFilter.value = '';
    if (startDateFilter) startDateFilter.value = '';
    if (endDateFilter) endDateFilter.value = '';
    
    loadManagerRequests();
}

// Excel Export Function
async function exportTeamRequestsToExcel() {
    const exportBtn = document.getElementById('exportToExcel');
    
    // Check if button is already disabled (no data to export)
    if (exportBtn && exportBtn.disabled) {
        return;
    }
    
    try {
        // Disable button and show loading state
        if (exportBtn) {
            exportBtn.disabled = true;
            exportBtn.innerHTML = '<span class="btn-icon">⏳</span>Exporting...';
        }
        
        // Build query parameters from current filters
        const params = new URLSearchParams();
        
        if (currentRequestFilters.status) {
            params.append('status', currentRequestFilters.status);
        }
        if (currentRequestFilters.employee_id) {
            params.append('employee_id', currentRequestFilters.employee_id);
        }
        if (currentRequestFilters.leave_type) {
            params.append('leave_type', currentRequestFilters.leave_type);
        }
        if (currentRequestFilters.start_date) {
            params.append('start_date', currentRequestFilters.start_date);
        }
        if (currentRequestFilters.end_date) {
            params.append('end_date', currentRequestFilters.end_date);
        }
        
        // Always specify Excel format
        params.append('format', 'excel');
        
        const url = `/manager/export-team-requests?${params.toString()}`;
        
        // Create a temporary anchor element to trigger download
        const link = document.createElement('a');
        link.href = url;
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
    } catch (error) {
        console.error('Error exporting to Excel:', error);
        alert(`Failed to export data to Excel: ${error.message}`);
    } finally {
        // Re-enable button
        if (exportBtn) {
            exportBtn.disabled = false;
            exportBtn.innerHTML = '<span class="btn-icon">📊</span>Export to Excel';
        }
    }
}

// System Administration Functions (Admin only)
function manageUsers() {
    showUserManagementModal();
}

function manageLeaveTypes() {
    showLeaveTypesModal();
}

// ===== USER MANAGEMENT FUNCTIONALITY =====

let currentUsers = [];
let currentFilters = {};

// Show user management modal
function showUserManagementModal() {
    // Create modal if it doesn't exist
    if (!document.getElementById('userManagementModal')) {
        createUserManagementModal();
    }
    
    // Show modal
    document.getElementById('userManagementModal').style.display = 'flex';
    document.body.style.overflow = 'hidden';
    
    // Reset filters
    currentFilters = {};
    const roleFilter = document.getElementById('roleFilter');
    const statusFilter = document.getElementById('userStatusFilter');
    const searchInput = document.getElementById('userSearch');
    
    if (roleFilter) roleFilter.value = '';
    if (statusFilter) statusFilter.value = '';
    if (searchInput) searchInput.value = '';
    
    // Load users
    loadUsers();
}

// Create user management modal HTML
function createUserManagementModal() {
    const modalHTML = `
        <div id="userManagementModal" class="admin-modal">
            <div class="admin-modal-content">
                <div class="admin-modal-header">
                    <h2>👤 User Management</h2>
                    <button class="admin-modal-close" onclick="closeUserManagementModal()">&times;</button>
                </div>
                
                <div class="admin-modal-body">
                    <!-- Search and Filter Controls -->
                    <div class="user-controls">
                        <div class="user-search">
                            <input type="text" id="userSearch" placeholder="Search by name or email..." 
                                   onkeyup="handleUserSearch()" class="search-input">
                        </div>
                        <div class="user-filters">
                            <select id="roleFilter" onchange="handleFilterChange()" class="filter-select">
                                <option value="">All Roles</option>
                                <option value="admin">Admin</option>
                                <option value="manager">Manager</option>
                                <option value="employee">Employee</option>
                            </select>
                            <select id="userStatusFilter" onchange="handleFilterChange()" class="filter-select">
                                <option value="">All Status</option>
                                <option value="active">Active</option>
                                <option value="inactive">Inactive</option>
                            </select>
                        </div>
                        <button class="btn btn-primary" onclick="showAddUserForm()">
                            <span class="btn-icon">➕</span>Add New User
                        </button>
                    </div>
                    
                    <!-- Users Table -->
                    <div class="users-table-container">
                        <table id="usersTable" class="users-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Name</th>
                                    <th>Email</th>
                                    <th>Role</th>
                                    <th>Manager</th>
                                    <th>Status</th>
                                    <th>Leave Balance</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="usersTableBody">
                                <tr>
                                    <td colspan="8" class="loading-row">
                                        <div class="loading-spinner"></div>
                                        Loading users...
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    
                    <div class="users-summary">
                        <span id="userCount">0 users</span>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modalHTML);
}

// Close user management modal
function closeUserManagementModal() {
    document.getElementById('userManagementModal').style.display = 'none';
    document.body.style.overflow = 'auto';
}

// Load users from API
async function loadUsers(filters = {}) {
    try {
        // Show loading state
        const tbody = document.getElementById('usersTableBody');
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="loading-row">
                    <div class="loading-spinner"></div>
                    Loading users...
                </td>
            </tr>
        `;
        
        // Build query parameters
        const params = new URLSearchParams();
        if (filters.role) params.append('role', filters.role);
        if (filters.status) params.append('status', filters.status);
        if (filters.search) params.append('search', filters.search);
        
        const url = `/admin/users${params.toString() ? '?' + params.toString() : ''}`;
        
        // Debug: Log the URL and filters being sent
        console.log('Loading users with filters:', filters);
        console.log('Request URL:', url);
        
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            currentUsers = data.data;
            currentFilters = filters;
            renderUsersTable(data.data);
            updateUserCount(data.count);
        } else {
            throw new Error(data.message || 'Failed to load users');
        }
        
    } catch (error) {
        console.error('Error loading users:', error);
        
        const tbody = document.getElementById('usersTableBody');
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="error-row">
                    <span class="error-icon">⚠️</span>
                    Error loading users: ${error.message}
                    <button class="retry-btn" onclick="loadUsers(currentFilters)">Retry</button>
                </td>
            </tr>
        `;
    }
}

// Render users table
function renderUsersTable(users) {
    const tbody = document.getElementById('usersTableBody');
    
    if (users.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="empty-row">
                    <span class="empty-icon">👥</span>
                    No users found matching the current filters.
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = users.map(user => `
        <tr class="user-row ${user.status === 'inactive' ? 'inactive-user' : ''}">
            <td>${user.id}</td>
            <td>
                <div class="user-name">
                    ${escapeHtml(user.name || 'N/A')}
                </div>
            </td>
            <td>
                <div class="user-email">${escapeHtml(user.email)}</div>
            </td>
            <td>
                <span class="role-badge role-${user.role}">${user.role}</span>
            </td>
            <td>
                <div class="manager-info">
                    ${user.manager_name ? escapeHtml(user.manager_name) : 'N/A'}
                    ${user.manager_email ? `<br><small>${escapeHtml(user.manager_email)}</small>` : ''}
                </div>
            </td>
            <td>
                <span class="status-badge status-${user.status}">${user.status}</span>
            </td>
            <td>
                <div class="leave-balance">
                    <small>A: ${user.leave_balances.annual} | M: ${user.leave_balances.medical} | O: ${user.leave_balances.other}</small>
                </div>
            </td>
            <td>
                <div class="user-actions">
                    <button class="btn-small btn-secondary" onclick="showEditUserForm(${user.id})" title="Edit User">
                        ✏️
                    </button>
                    ${user.status === 'active' ? 
                        `<button class="btn-small btn-danger" onclick="deactivateUser(${user.id})" title="Deactivate User">
                            🚫 Deactivate
                        </button>` : 
                        `<button class="btn-small btn-success" onclick="reactivateUser(${user.id})" title="Reactivate User">
                            ✅ Reactivate
                        </button>`
                    }
                </div>
            </td>
        </tr>
    `).join('');
}

// Update user count display
function updateUserCount(count) {
    document.getElementById('userCount').textContent = `${count} user${count !== 1 ? 's' : ''}`;
}

// Handle search input
function handleUserSearch() {
    const searchTerm = document.getElementById('userSearch').value.trim();
    const filters = { ...currentFilters, search: searchTerm || undefined };
    
    // Debounce search
    clearTimeout(window.searchTimeout);
    window.searchTimeout = setTimeout(() => {
        loadUsers(filters);
    }, 300);
}

// Handle filter changes
function handleFilterChange() {
    const roleFilterElement = document.getElementById('roleFilter');
    const statusFilterElement = document.getElementById('userStatusFilter');
    const searchInput = document.getElementById('userSearch');
    
    console.log('handleFilterChange called:');
    console.log('  roleFilter element:', roleFilterElement);
    console.log('  statusFilter element:', statusFilterElement);
    console.log('  roleFilter element exists:', !!roleFilterElement);
    console.log('  statusFilter element exists:', !!statusFilterElement);
    
    const roleFilter = roleFilterElement ? roleFilterElement.value : '';
    const statusFilter = statusFilterElement ? statusFilterElement.value : '';
    const searchTerm = searchInput ? searchInput.value.trim() : '';
    
    console.log('  roleFilter value:', roleFilter);
    console.log('  statusFilter value:', statusFilter);
    console.log('  searchTerm:', searchTerm);
    
    const filters = {};
    
    // Only add non-empty filter values
    if (roleFilter && roleFilter.trim()) {
        filters.role = roleFilter;
    }
    if (statusFilter && statusFilter.trim()) {
        filters.status = statusFilter;
    }
    if (searchTerm && searchTerm.trim()) {
        filters.search = searchTerm;
    }
    
    console.log('  filters object:', filters);
    
    loadUsers(filters);
}

// Helper function to escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Helper function to escape JavaScript strings for use in onclick attributes
function escapeJavaScript(text) {
    if (!text) return '';
    return text.replace(/\\/g, '\\\\')
               .replace(/'/g, "\\'")
               .replace(/"/g, '\\"')
               .replace(/\n/g, '\\n')
               .replace(/\r/g, '\\r')
               .replace(/\t/g, '\\t');
}

// ===== ADD/EDIT USER FORM =====

// Show add user form
function showAddUserForm() {
    showUserForm();
}

// Show edit user form
function showEditUserForm(userId) {
    const user = currentUsers.find(u => u.id === userId);
    if (user) {
        showUserForm(user);
    } else {
        alert('User not found. Please refresh the user list.');
    }
}

// Show user form (add or edit)
async function showUserForm(user = null) {
    const isEdit = user !== null;
    const title = isEdit ? 'Edit User' : 'Add New User';
    
    // Create form modal if it doesn't exist
    if (!document.getElementById('userFormModal')) {
        createUserFormModal();
    }
    
    // Update modal title
    document.querySelector('#userFormModal .admin-modal-header h3').textContent = title;
    
    // Show form modal
    document.getElementById('userFormModal').style.display = 'flex';
    
    // Populate form (async to ensure manager dropdown loads first)
    await populateUserForm(user);
}

// Create user form modal HTML
function createUserFormModal() {
    const formModalHTML = `
        <div id="userFormModal" class="admin-modal admin-form-modal">
            <div class="admin-modal-content">
                <div class="admin-modal-header">
                    <h3>Add New User</h3>
                    <button class="admin-modal-close" onclick="closeUserForm()">&times;</button>
                </div>
                
                <div class="admin-modal-body">
                    <form id="userForm" onsubmit="handleUserFormSubmit(event)">
                        <div class="form-grid">
                            <div class="form-group">
                                <label for="userName" class="form-label">Full Name *</label>
                                <input type="text" id="userName" name="name" class="form-input" 
                                       placeholder="Enter full name" required>
                                <div class="form-error" id="nameError"></div>
                            </div>
                            
                            <div class="form-group">
                                <label for="userEmail" class="form-label">Email Address *</label>
                                <input type="email" id="userEmail" name="email" class="form-input" 
                                       placeholder="Enter email address" required>
                                <div class="form-error" id="emailError"></div>
                            </div>
                            
                            <div class="form-group">
                                <label for="userRole" class="form-label">Role *</label>
                                <select id="userRole" name="role" class="form-select" required onchange="handleRoleChange()">
                                    <option value="">Select Role</option>
                                    <option value="admin">Admin</option>
                                    <option value="manager">Manager</option>
                                    <option value="employee">Employee</option>
                                </select>
                                <div class="form-error" id="roleError"></div>
                            </div>
                            
                            <div class="form-group" id="managerGroup">
                                <label for="userManager" class="form-label">Manager</label>
                                <select id="userManager" name="manager_id" class="form-select">
                                    <option value="">Select Manager</option>
                                </select>
                                <div class="form-error" id="managerError"></div>
                            </div>
                            
                            <div class="form-group" id="passwordGroup">
                                <label for="userPassword" class="form-label">Password *</label>
                                <input type="password" id="userPassword" name="password" class="form-input" 
                                       placeholder="Enter password (min 8 characters)" minlength="8">
                                <div class="form-error" id="passwordError"></div>
                            </div>
                            
                            <div class="form-group">
                                <label for="annualLeave" class="form-label">Annual Leave Balance</label>
                                <input type="number" id="annualLeave" name="annual_leave_balance" 
                                       class="form-input" value="10" min="0" max="365" step="0.5">
                            </div>
                            
                            <div class="form-group">
                                <label for="medicalLeave" class="form-label">Medical Leave Balance</label>
                                <input type="number" id="medicalLeave" name="medical_leave_balance" 
                                       class="form-input" value="14" min="0" max="365" step="0.5">
                            </div>
                            
                            <div class="form-group">
                                <label for="otherLeave" class="form-label">Other Leave Balance</label>
                                <input type="number" id="otherLeave" name="other_leave_balance" 
                                       class="form-input" value="5" min="0" max="365" step="0.5">
                            </div>
                        </div>
                        
                        <div class="form-actions">
                            <button type="button" class="btn btn-secondary" onclick="closeUserForm()">
                                Cancel
                            </button>
                            <button type="submit" class="btn btn-primary" id="userFormSubmit">
                                <span class="btn-icon">💾</span>
                                <span class="btn-text">Save User</span>
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', formModalHTML);
}

// Populate user form with data
async function populateUserForm(user) {
    const form = document.getElementById('userForm');
    form.reset();
    
    // Load managers for dropdown first
    await loadManagersDropdown();
    
    if (user) {
        // Edit mode - populate with existing data
        document.getElementById('userName').value = user.name || '';
        document.getElementById('userEmail').value = user.email || '';
        document.getElementById('userRole').value = user.role || '';
        document.getElementById('userManager').value = user.manager_id || '';
        document.getElementById('annualLeave').value = user.leave_balances.annual || 10;
        document.getElementById('medicalLeave').value = user.leave_balances.medical || 14;
        document.getElementById('otherLeave').value = user.leave_balances.other || 5;
        
        // Hide password field for edit mode
        document.getElementById('passwordGroup').style.display = 'none';
        document.getElementById('userPassword').required = false;
        
        // Store user ID for update
        form.dataset.userId = user.id;
        document.getElementById('userFormSubmit').innerHTML = `
            <span class="btn-icon">✏️</span>
            <span class="btn-text">Update User</span>
        `;
    } else {
        // Add mode - show password field
        document.getElementById('passwordGroup').style.display = 'block';
        document.getElementById('userPassword').required = true;
        
        // Remove user ID
        delete form.dataset.userId;
        document.getElementById('userFormSubmit').innerHTML = `
            <span class="btn-icon">➕</span>
            <span class="btn-text">Create User</span>
        `;
    }
    
    // Handle role change
    handleRoleChange();
}

// Load managers dropdown
async function loadManagersDropdown() {
    try {
        const response = await fetch('/admin/users?role=manager');
        const data = await response.json();
        
        if (data.success) {
            const managerSelect = document.getElementById('userManager');
            managerSelect.innerHTML = '<option value="">Select Manager</option>';
            
            // Add managers and admins
            const managers = data.data.filter(user => ['manager', 'admin'].includes(user.role) && user.status === 'active');
            
            managers.forEach(manager => {
                const option = document.createElement('option');
                option.value = manager.id;
                option.textContent = `${manager.name || manager.email} (${manager.role})`;
                managerSelect.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Error loading managers:', error);
    }
}

// Handle role change
function handleRoleChange() {
    const role = document.getElementById('userRole').value;
    const managerGroup = document.getElementById('managerGroup');
    const managerSelect = document.getElementById('userManager');
    
    if (role === 'admin') {
        managerGroup.style.display = 'none';
        managerSelect.required = false;
        managerSelect.value = '';
    } else {
        managerGroup.style.display = 'block';
        managerSelect.required = true;
    }
}

// Close user form
function closeUserForm() {
    document.getElementById('userFormModal').style.display = 'none';
    clearFormErrors();
}

// Handle user form submit
async function handleUserFormSubmit(event) {
    event.preventDefault();
    
    const form = event.target;
    const isEdit = !!form.dataset.userId;
    const userId = form.dataset.userId;
    
    // Clear previous errors
    clearFormErrors();
    
    // Get form data
    const formData = new FormData(form);
    const userData = Object.fromEntries(formData);
    
    // For edit mode, remove password field since we use separate reset functionality
    if (isEdit) {
        delete userData.password;
    }
    
    // Client-side validation
    if (!validateUserForm(userData, isEdit)) {
        return;
    }
    
    // Show loading state
    const submitBtn = document.getElementById('userFormSubmit');
    const originalHTML = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="loading-spinner"></span> Saving...';
    
    try {
        let response;
        
        if (isEdit) {
            // Update user
            response = await fetch(`/admin/users/${userId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(userData)
            });
        } else {
            // Create user
            response = await fetch('/admin/users', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(userData)
            });
        }
        
        const data = await response.json();
        
        if (data.success) {
            // Show success message
            showNotification(`User ${isEdit ? 'updated' : 'created'} successfully!`, 'success');
            
            // Close form and reload users
            closeUserForm();
            loadUsers(currentFilters);
            loadTotalUsersCount(); // Update dashboard card count
        } else {
            // Handle validation errors
            handleFormErrors(data);
        }
        
    } catch (error) {
        console.error('Error saving user:', error);
        showNotification('Error saving user. Please try again.', 'error');
    } finally {
        // Restore button
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalHTML;
    }
}

// Validate user form
function validateUserForm(userData, isEdit) {
    let isValid = true;
    
    // Name validation
    if (!userData.name || userData.name.trim().length < 2) {
        showFieldError('nameError', 'Name must be at least 2 characters long');
        isValid = false;
    }
    
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!userData.email || !emailRegex.test(userData.email)) {
        showFieldError('emailError', 'Please enter a valid email address');
        isValid = false;
    }
    
    // Password validation (only for new users)
    if (!isEdit && (!userData.password || userData.password.length < 8)) {
        showFieldError('passwordError', 'Password must be at least 8 characters long');
        isValid = false;
    }
    
    // Role validation
    if (!userData.role) {
        showFieldError('roleError', 'Please select a role');
        isValid = false;
    }
    
    // Manager validation (for non-admin roles)
    if (userData.role && userData.role !== 'admin' && !userData.manager_id) {
        showFieldError('managerError', 'Please select a manager');
        isValid = false;
    }
    
    return isValid;
}

// Show field error
function showFieldError(errorId, message) {
    const errorElement = document.getElementById(errorId);
    errorElement.textContent = message;
    errorElement.style.display = 'block';
}

// Clear form errors
function clearFormErrors() {
    const errorElements = document.querySelectorAll('.form-error');
    errorElements.forEach(element => {
        element.textContent = '';
        element.style.display = 'none';
    });
}

// Handle form errors from server
function handleFormErrors(data) {
    if (data.message) {
        showNotification(data.message, 'error');
    }
    
    // Handle specific field errors if provided
    if (data.errors) {
        Object.keys(data.errors).forEach(field => {
            const errorId = field + 'Error';
            if (document.getElementById(errorId)) {
                showFieldError(errorId, data.errors[field]);
            }
        });
    }
}

// ===== USER ACTIONS =====


// Deactivate user
async function deactivateUser(userId) {
    const user = currentUsers.find(u => u.id === userId);
    if (!user) {
        alert('User not found. Please refresh the user list.');
        return;
    }
    
    const confirmed = confirm(
        `Deactivate ${user.name || user.email}?\n\n` +
        `This will:\n` +
        `• Set the user as inactive\n` +
        `• Prevent them from logging in\n` +
        `• Unassign any employees they manage\n` +
        `• Preserve their leave history\n\n` +
        `This action can be reversed by editing the user.`
    );
    
    if (!confirmed) return;
    
    try {
        const response = await fetch(`/admin/users/${userId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            let message = `User ${user.name || user.email} deactivated successfully!`;
            
            if (data.data.managed_employees_affected > 0) {
                message += `\n\n${data.data.managed_employees_affected} managed employee(s) have been unassigned.`;
            }
            
            showNotification(message, 'success');
            
            // Reload users to reflect changes
            loadUsers(currentFilters);
        } else {
            throw new Error(data.message || 'Failed to deactivate user');
        }
        
    } catch (error) {
        console.error('Error deactivating user:', error);
        showNotification('Error deactivating user: ' + error.message, 'error');
    }
}

// Reactivate user
async function reactivateUser(userId) {
    const user = currentUsers.find(u => u.id === userId);
    if (!user) {
        alert('User not found. Please refresh the user list.');
        return;
    }
    
    const confirmed = confirm(
        `Reactivate ${user.name || user.email}?\n\n` +
        `This will:\n` +
        `• Set the user as active\n` +
        `• Allow them to log in again\n` +
        `• They can be assigned employees to manage\n\n` +
        `Are you sure you want to reactivate this user?`
    );
    
    if (!confirmed) return;
    
    try {
        const response = await fetch(`/admin/users/${userId}/activate`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification(`User ${user.name || user.email} reactivated successfully!`, 'success');
            
            // Reload users to reflect changes
            loadUsers(currentFilters);
        } else {
            throw new Error(data.message || 'Failed to reactivate user');
        }
        
    } catch (error) {
        console.error('Error reactivating user:', error);
        showNotification('Error reactivating user: ' + error.message, 'error');
    }
}

// ===== NOTIFICATION SYSTEM =====

// Show notification
function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existingNotifications = document.querySelectorAll('.admin-notification');
    existingNotifications.forEach(n => n.remove());
    
    const notificationHTML = `
        <div class="admin-notification notification-${type}">
            <div class="notification-content">
                <span class="notification-icon">
                    ${type === 'success' ? '✅' : type === 'error' ? '❌' : 'ℹ️'}
                </span>
                <span class="notification-message">${escapeHtml(message)}</span>
            </div>
            <button class="notification-close" onclick="this.parentElement.remove()">&times;</button>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', notificationHTML);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        const notification = document.querySelector('.admin-notification');
        if (notification) {
            notification.remove();
        }
    }, 5000);
}


// Initialize manager functionality on page load
document.addEventListener('DOMContentLoaded', function() {
    setupManagerFilters();
    
    // Setup modal close handlers for manager modals
    const managerModalCloseBtn = document.getElementById('closeManagerModal');
    const approvalModalCloseBtn = document.getElementById('closeApprovalModal');
    const rejectionModalCloseBtn = document.getElementById('closeRejectionModal');
    
    if (managerModalCloseBtn) {
        managerModalCloseBtn.addEventListener('click', closeManagerModal);
    }
    
    if (approvalModalCloseBtn) {
        approvalModalCloseBtn.addEventListener('click', closeApprovalModal);
    }
    
    if (rejectionModalCloseBtn) {
        rejectionModalCloseBtn.addEventListener('click', closeRejectionModal);
    }
    
    // Setup modal background click handlers
    const managerModal = document.getElementById('managerRequestDetailsModal');
    const approvalModal = document.getElementById('approvalModal');
    const rejectionModal = document.getElementById('rejectionModal');
    
    if (managerModal) {
        managerModal.addEventListener('click', function(e) {
            if (e.target === managerModal) {
                closeManagerModal();
            }
        });
    }
    
    if (approvalModal) {
        approvalModal.addEventListener('click', function(e) {
            if (e.target === approvalModal) {
                closeApprovalModal();
            }
        });
    }
    
    if (rejectionModal) {
        rejectionModal.addEventListener('click', function(e) {
            if (e.target === rejectionModal) {
                closeRejectionModal();
            }
        });
    }
    
    // ESC key to close modals
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeManagerModal();
            closeApprovalModal();
            closeRejectionModal();
            closeLeaveTypesModal();
        }
    });
});

// ===== LEAVE TYPES MANAGEMENT FUNCTIONALITY =====

let currentLeaveTypes = [];

function showLeaveTypesModal() {
    // Create modal if it doesn't exist
    if (!document.getElementById('leaveTypesModal')) {
        createLeaveTypesModal();
    }
    
    // Show modal
    document.getElementById('leaveTypesModal').style.display = 'flex';
    document.body.style.overflow = 'hidden';
    
    // Load leave types
    loadLeaveTypes();
}

// Create leave types management modal HTML
function createLeaveTypesModal() {
    const modalHTML = `
        <div id="leaveTypesModal" class="admin-modal">
            <div class="admin-modal-content">
                <div class="admin-modal-header">
                    <h2>⚙️ Leave Types Management</h2>
                    <button class="admin-modal-close" onclick="closeLeaveTypesModal()">&times;</button>
                </div>
                
                <div class="admin-modal-body">
                    <!-- Add New Leave Type Form -->
                    <div class="leave-type-add-section">
                        <h3>Add New Leave Type</h3>
                        <form id="addLeaveTypeForm" class="leave-type-form" onsubmit="addLeaveType(event)">
                            <div class="form-group">
                                <input type="text" id="newLeaveTypeName" placeholder="Enter leave type name" 
                                       maxlength="50" minlength="3" required class="form-input">
                                <button type="submit" class="btn btn-primary">Add Leave Type</button>
                            </div>
                            <div id="addLeaveTypeError" class="error-message"></div>
                        </form>
                    </div>
                    
                    <!-- Leave Types List -->
                    <div class="leave-types-list">
                        <h3>Existing Leave Types</h3>
                        <div id="leaveTypesContainer">
                            <div id="leaveTypesLoading" class="loading-message">Loading leave types...</div>
                            <div id="leaveTypesTable" class="leave-types-table" style="display: none;">
                                <div class="table-header">
                                    <div>ID</div>
                                    <div>Leave Type</div>
                                    <div>Actions</div>
                                </div>
                                <div id="leaveTypesTableBody"></div>
                            </div>
                            <div id="noLeaveTypes" class="no-data-message" style="display: none;">
                                No leave types found. Add your first leave type above.
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="admin-modal-footer">
                    <button class="btn btn-secondary" onclick="closeLeaveTypesModal()">Close</button>
                </div>
            </div>
        </div>
        
        <!-- Edit Leave Type Modal -->
        <div id="editLeaveTypeModal" class="admin-modal">
            <div class="admin-modal-content admin-modal-small">
                <div class="admin-modal-header">
                    <h3>Edit Leave Type</h3>
                    <button class="admin-modal-close" onclick="closeEditLeaveTypeModal()">&times;</button>
                </div>
                <div class="admin-modal-body">
                    <form id="editLeaveTypeForm" onsubmit="updateLeaveType(event)">
                        <input type="hidden" id="editLeaveTypeId">
                        <div class="form-group">
                            <label for="editLeaveTypeName">Leave Type Name:</label>
                            <input type="text" id="editLeaveTypeName" required maxlength="50" minlength="3" class="form-input">
                        </div>
                        <div id="editLeaveTypeError" class="error-message"></div>
                        <div class="form-actions">
                            <button type="button" class="btn btn-secondary" onclick="closeEditLeaveTypeModal()">Cancel</button>
                            <button type="submit" class="btn btn-primary">Update</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <!-- Delete Confirmation Modal -->
        <div id="deleteLeaveTypeModal" class="admin-modal">
            <div class="admin-modal-content admin-modal-small">
                <div class="admin-modal-header">
                    <h3>Confirm Deletion</h3>
                    <button class="admin-modal-close" onclick="closeDeleteLeaveTypeModal()">&times;</button>
                </div>
                <div class="admin-modal-body">
                    <p>Are you sure you want to delete the leave type "<strong id="deleteLeaveTypeName"></strong>"?</p>
                    <p class="warning-text">This action cannot be undone. Leave types with existing requests cannot be deleted.</p>
                    <div class="form-actions">
                        <button type="button" class="btn btn-secondary" onclick="closeDeleteLeaveTypeModal()">Cancel</button>
                        <button type="button" class="btn btn-danger" onclick="confirmDeleteLeaveType()">Delete</button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modalHTML);
}

function closeLeaveTypesModal() {
    const modal = document.getElementById('leaveTypesModal');
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
    }
}

// Load leave types from server
async function loadLeaveTypes() {
    try {
        showLeaveTypesLoading(true);
        
        const response = await fetch('/admin/leave-types');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        currentLeaveTypes = data.success ? data.data : [];
        renderLeaveTypesTable();
        
    } catch (error) {
        console.error('Error loading leave types:', error);
        showLeaveTypesMessage('Failed to load leave types. Please try again.', 'error');
    } finally {
        showLeaveTypesLoading(false);
    }
}

// Add new leave type
async function addLeaveType(event) {
    event.preventDefault();
    
    const nameInput = document.getElementById('newLeaveTypeName');
    const type = nameInput.value.trim();
    
    clearLeaveTypeError('addLeaveTypeError');
    
    if (!validateLeaveTypeName(type, 'addLeaveTypeError')) {
        return;
    }
    
    try {
        const response = await fetch('/admin/leave-types', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ type })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Failed to add leave type');
        }
        
        // Success
        nameInput.value = '';
        showLeaveTypesMessage('Leave type added successfully', 'success');
        loadLeaveTypes(); // Reload the table
        loadLeaveTypesCount(); // Update dashboard card count
        
    } catch (error) {
        console.error('Error adding leave type:', error);
        showLeaveTypeError('addLeaveTypeError', error.message);
    }
}

// Render leave types table
function renderLeaveTypesTable() {
    const tableBody = document.getElementById('leaveTypesTableBody');
    const table = document.getElementById('leaveTypesTable');
    const noDataMessage = document.getElementById('noLeaveTypes');
    
    if (currentLeaveTypes.length === 0) {
        table.style.display = 'none';
        noDataMessage.style.display = 'block';
        return;
    }
    
    noDataMessage.style.display = 'none';
    table.style.display = 'block';
    
    tableBody.innerHTML = currentLeaveTypes.map(leaveType => `
        <div class="table-row">
            <div>${leaveType.id}</div>
            <div>${escapeHtml(leaveType.type)}</div>
            <div class="table-actions">
                <button class="btn-small btn-secondary" onclick="showEditLeaveTypeModal(${leaveType.id}, '${escapeJavaScript(leaveType.type)}')" title="Edit">
                    ✏️
                </button>
                <button class="btn-small btn-danger" onclick="showDeleteLeaveTypeModal(${leaveType.id}, '${escapeJavaScript(leaveType.type)}')" title="Delete">
                    🗑️
                </button>
            </div>
        </div>
    `).join('');
}

// Show edit leave type modal
function showEditLeaveTypeModal(id, type) {
    document.getElementById('editLeaveTypeId').value = id;
    document.getElementById('editLeaveTypeName').value = type;
    clearLeaveTypeError('editLeaveTypeError');
    document.getElementById('editLeaveTypeModal').style.display = 'flex';
}

function closeEditLeaveTypeModal() {
    document.getElementById('editLeaveTypeModal').style.display = 'none';
}

// Update leave type
async function updateLeaveType(event) {
    event.preventDefault();
    
    const id = document.getElementById('editLeaveTypeId').value;
    const type = document.getElementById('editLeaveTypeName').value.trim();
    
    clearLeaveTypeError('editLeaveTypeError');
    
    if (!validateLeaveTypeName(type, 'editLeaveTypeError')) {
        return;
    }
    
    try {
        const response = await fetch(`/admin/leave-types/${id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ type })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Failed to update leave type');
        }
        
        // Success
        closeEditLeaveTypeModal();
        showLeaveTypesMessage('Leave type updated successfully', 'success');
        loadLeaveTypes(); // Reload the table
        loadLeaveTypesCount(); // Update dashboard card count
        
    } catch (error) {
        console.error('Error updating leave type:', error);
        showLeaveTypeError('editLeaveTypeError', error.message);
    }
}

// Show delete confirmation modal
function showDeleteLeaveTypeModal(id, type) {
    document.getElementById('deleteLeaveTypeName').textContent = type;
    document.getElementById('deleteLeaveTypeModal').style.display = 'flex';
    document.getElementById('deleteLeaveTypeModal').setAttribute('data-delete-id', id);
}

function closeDeleteLeaveTypeModal() {
    document.getElementById('deleteLeaveTypeModal').style.display = 'none';
}

// Confirm delete leave type
async function confirmDeleteLeaveType() {
    const modal = document.getElementById('deleteLeaveTypeModal');
    const id = modal.getAttribute('data-delete-id');
    
    try {
        const response = await fetch(`/admin/leave-types/${id}`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Failed to delete leave type');
        }
        
        // Success
        closeDeleteLeaveTypeModal();
        showLeaveTypesMessage('Leave type deleted successfully', 'success');
        loadLeaveTypes(); // Reload the table
        loadLeaveTypesCount(); // Update dashboard card count
        
    } catch (error) {
        console.error('Error deleting leave type:', error);
        showLeaveTypesMessage(`Failed to delete leave type: ${error.message}`, 'error');
    }
}

// Validation helpers
function validateLeaveTypeName(type, errorElementId) {
    if (!type) {
        showLeaveTypeError(errorElementId, 'Leave type name is required');
        return false;
    }
    
    if (type.length < 3) {
        showLeaveTypeError(errorElementId, 'Leave type name must be at least 3 characters long');
        return false;
    }
    
    if (type.length > 50) {
        showLeaveTypeError(errorElementId, 'Leave type name must not exceed 50 characters');
        return false;
    }
    
    // Check for special characters that might indicate XSS attempts
    const dangerousChars = /[<>'"&]/;
    if (dangerousChars.test(type)) {
        showLeaveTypeError(errorElementId, 'Leave type name contains invalid characters');
        return false;
    }
    
    return true;
}

// UI helper functions
function showLeaveTypesLoading(show) {
    const loading = document.getElementById('leaveTypesLoading');
    const table = document.getElementById('leaveTypesTable');
    const noData = document.getElementById('noLeaveTypes');
    
    if (show) {
        loading.style.display = 'block';
        table.style.display = 'none';
        noData.style.display = 'none';
    } else {
        loading.style.display = 'none';
    }
}

function showLeaveTypeError(elementId, message) {
    const errorElement = document.getElementById(elementId);
    if (errorElement) {
        errorElement.textContent = message;
        errorElement.style.display = 'block';
    }
}

function clearLeaveTypeError(elementId) {
    const errorElement = document.getElementById(elementId);
    if (errorElement) {
        errorElement.textContent = '';
        errorElement.style.display = 'none';
    }
}

function showLeaveTypesMessage(message, type = 'info') {
    // Create or update message in the modal
    let messageContainer = document.querySelector('#leaveTypesModal .message-container');
    if (!messageContainer) {
        messageContainer = document.createElement('div');
        messageContainer.className = 'message-container';
        const modalBody = document.querySelector('#leaveTypesModal .admin-modal-body');
        modalBody.insertBefore(messageContainer, modalBody.firstChild);
    }
    
    messageContainer.innerHTML = `<div class="message message-${type}">${message}</div>`;
    
    // Auto-hide success messages after 3 seconds
    if (type === 'success') {
        setTimeout(() => {
            if (messageContainer) {
                messageContainer.innerHTML = '';
            }
        }, 3000);
    }
}