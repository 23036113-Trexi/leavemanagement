document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('leaveRequestForm');
    const startDateInput = document.getElementById('startDate');
    const endDateInput = document.getElementById('endDate');
    const numberOfDaysInput = document.getElementById('numberOfDays');
    const halfDayRadios = document.querySelectorAll('input[name="half_day"]');
    const messageContainer = document.getElementById('messageContainer');
    const messageContent = document.getElementById('messageContent');
    const leaveTypeSelect = document.getElementById('leaveType');
    const supportingDocumentGroup = document.getElementById('supportingDocumentGroup');
    const supportingDocumentInput = document.getElementById('supportingDocument');
    
    // No need to get user_id from URL anymore - using session-based authentication

    // Set minimum date to today by default
    const today = new Date().toISOString().split('T')[0];
    startDateInput.min = today;
    endDateInput.min = today;

    // Calculate number of days when dates change
    function calculateDays() {
        const startDate = new Date(startDateInput.value);
        const endDate = new Date(endDateInput.value);
        const halfDayValue = document.querySelector('input[name="half_day"]:checked').value;

        if (startDateInput.value && endDateInput.value) {
            if (endDate < startDate) {
                showMessage('End date cannot be before start date', 'error');
                numberOfDaysInput.value = '';
                return;
            }

            // Calculate working days (excluding weekends)
            let days = 0;
            const currentDate = new Date(startDate);
            
            while (currentDate <= endDate) {
                const dayOfWeek = currentDate.getDay();
                // Monday = 1, Friday = 5 (exclude weekends)
                if (dayOfWeek !== 0 && dayOfWeek !== 6) {
                    days++;
                }
                currentDate.setDate(currentDate.getDate() + 1);
            }

            // Adjust for half day
            if (halfDayValue === 'AM' || halfDayValue === 'PM') {
                if (startDate.getTime() === endDate.getTime()) {
                    days = 0.5;
                } else {
                    // If it's a range with half day, assume half day applies to start or end
                    days = days - 0.5;
                }
            }

            numberOfDaysInput.value = days;
            hideMessage();
        }
    }

    // Event listeners for date calculation
    startDateInput.addEventListener('change', function() {
        const selectedOption = leaveTypeSelect.options[leaveTypeSelect.selectedIndex];
        const leaveTypeText = selectedOption.text.toLowerCase().trim();
        
        if (leaveTypeText.includes('medical')) {
            // For medical leave, end date minimum should be the start date (not today)
            endDateInput.min = this.value;
        } else {
            // For other leave types, end date minimum should be either start date or today, whichever is later
            endDateInput.min = this.value > today ? this.value : today;
        }
        calculateDays();
    });

    endDateInput.addEventListener('change', calculateDays);

    halfDayRadios.forEach(radio => {
        radio.addEventListener('change', calculateDays);
    });

    // Show/hide file upload and update date restrictions based on leave type
    function toggleFileUpload() {
        const selectedOption = leaveTypeSelect.options[leaveTypeSelect.selectedIndex];
        const leaveTypeText = selectedOption.text.toLowerCase().trim();
        
        // Show file upload for Medical Leave and Other Leaves (handle various cases)
        if (leaveTypeText.includes('medical') || leaveTypeText.includes('other')) {
            supportingDocumentGroup.style.display = 'block';
        } else {
            supportingDocumentGroup.style.display = 'none';
            // Clear file selection when hidden
            supportingDocumentInput.value = '';
        }
        
        // Update date restrictions based on leave type
        updateDateRestrictions();
    }
    
    // Update date minimum values based on leave type
    function updateDateRestrictions() {
        const selectedOption = leaveTypeSelect.options[leaveTypeSelect.selectedIndex];
        const leaveTypeText = selectedOption.text.toLowerCase().trim();
        
        if (leaveTypeText.includes('medical')) {
            // Allow backdating for medical leave - remove minimum date restriction
            startDateInput.removeAttribute('min');
            // If start date is selected, end date minimum should be start date
            if (startDateInput.value) {
                endDateInput.min = startDateInput.value;
            } else {
                endDateInput.removeAttribute('min');
            }
        } else {
            // For non-medical leave, set minimum date to today
            startDateInput.min = today;
            // If start date is selected, end date minimum should be either start date or today, whichever is later
            if (startDateInput.value) {
                endDateInput.min = startDateInput.value > today ? startDateInput.value : today;
            } else {
                endDateInput.min = today;
            }
        }
    }

    // Event listener for leave type changes
    leaveTypeSelect.addEventListener('change', toggleFileUpload);
    
    // Call toggleFileUpload on page load to handle any pre-selected values
    toggleFileUpload();

    // File validation
    function validateFile(file) {
        if (!file) return true; // File is optional
        
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'application/pdf', 
                             'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
        const maxSize = 5 * 1024 * 1024; // 5MB
        
        if (!allowedTypes.includes(file.type)) {
            showMessage('Invalid file type. Only JPG, PNG, PDF, DOC, and DOCX files are allowed.', 'error');
            return false;
        }
        
        if (file.size > maxSize) {
            showMessage('File size exceeds 5MB limit. Please choose a smaller file.', 'error');
            return false;
        }
        
        return true;
    }

    // File input change handler
    supportingDocumentInput.addEventListener('change', function() {
        if (this.files[0]) {
            validateFile(this.files[0]);
        }
    });

    // Form validation
    function validateForm() {
        let isValid = true;
        const requiredFields = form.querySelectorAll('[required]');

        requiredFields.forEach(field => {
            if (!field.value.trim()) {
                field.classList.add('invalid');
                isValid = false;
            } else {
                field.classList.remove('invalid');
                field.classList.add('valid');
            }
        });

        // Validate date range
        if (startDateInput.value && endDateInput.value) {
            const startDate = new Date(startDateInput.value);
            const endDate = new Date(endDateInput.value);
            
            if (endDate < startDate) {
                startDateInput.classList.add('invalid');
                endDateInput.classList.add('invalid');
                showMessage('End date cannot be before start date', 'error');
                isValid = false;
            }
        }

        // Validate future dates (except for medical leave which allows backdating)
        const todayDate = new Date();
        todayDate.setHours(0, 0, 0, 0);
        
        const selectedOption = leaveTypeSelect.options[leaveTypeSelect.selectedIndex];
        const leaveTypeText = selectedOption.text.toLowerCase().trim();
        const isMedicalLeave = leaveTypeText.includes('medical');
        
        if (startDateInput.value && !isMedicalLeave) {
            const startDate = new Date(startDateInput.value);
            if (startDate < todayDate) {
                startDateInput.classList.add('invalid');
                showMessage('Start date cannot be in the past', 'error');
                isValid = false;
            }
        }

        // Validate number of days
        if (!numberOfDaysInput.value || parseFloat(numberOfDaysInput.value) <= 0) {
            showMessage('Please select valid dates', 'error');
            isValid = false;
        }

        return isValid;
    }

    // Form submission
    form.addEventListener('submit', function(e) {
        e.preventDefault();

        if (!validateForm()) {
            return;
        }

        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = submitBtn.textContent;
        
        // Show loading state
        submitBtn.disabled = true;
        submitBtn.textContent = 'Submitting...';
        submitBtn.classList.add('loading');

        // Validate file if present
        const fileInput = supportingDocumentInput.files[0];
        if (fileInput && !validateFile(fileInput)) {
            // Reset button state
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
            submitBtn.classList.remove('loading');
            return;
        }

        // Prepare form data (use FormData for file upload support)
        const formData = new FormData(form);
        
        // User ID is handled by session authentication, no need to add it

        // Submit via fetch
        fetch('/submit-leave-request', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(result => {
            if (result.success) {
                showMessage('Leave request submitted successfully! Redirecting to dashboard...', 'success');
                
                // Redirect to dashboard after a short delay
                setTimeout(() => {
                    window.location.href = '/dashboard';
                }, 1500); // 1.5 second delay to show the success message
            } else {
                showMessage(result.message || 'Error submitting leave request', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showMessage('Network error. Please try again.', 'error');
        })
        .finally(() => {
            // Reset button state
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
            submitBtn.classList.remove('loading');
        });
    });

    // Real-time validation for required fields
    form.querySelectorAll('[required]').forEach(field => {
        field.addEventListener('blur', function() {
            if (this.value.trim()) {
                this.classList.remove('invalid');
                this.classList.add('valid');
            } else {
                this.classList.add('invalid');
                this.classList.remove('valid');
            }
        });

        field.addEventListener('input', function() {
            if (this.classList.contains('invalid') && this.value.trim()) {
                this.classList.remove('invalid');
                this.classList.add('valid');
            }
        });
    });

    // Character counter for reason field
    const reasonField = document.getElementById('reason');
    const helpText = reasonField.nextElementSibling;
    
    reasonField.addEventListener('input', function() {
        const remaining = 500 - this.value.length;
        helpText.textContent = `${remaining} characters remaining`;
        
        if (remaining < 50) {
            helpText.style.color = '#e74c3c';
        } else {
            helpText.style.color = '#6c757d';
        }
    });

    // Utility functions
    function showMessage(message, type) {
        messageContent.textContent = message;
        messageContainer.className = `message-container ${type}`;
        messageContainer.style.display = 'block';
        
        // Auto-hide success messages after 5 seconds
        if (type === 'success') {
            setTimeout(hideMessage, 5000);
        }
    }

    function hideMessage() {
        messageContainer.style.display = 'none';
    }

    // Reset form handler
    form.addEventListener('reset', function() {
        setTimeout(() => {
            numberOfDaysInput.value = '';
            hideMessage();
            // Hide file upload field
            supportingDocumentGroup.style.display = 'none';
            // Remove all validation classes
            form.querySelectorAll('.valid, .invalid').forEach(field => {
                field.classList.remove('valid', 'invalid');
            });
        }, 10);
    });
});