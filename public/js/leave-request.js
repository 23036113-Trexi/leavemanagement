document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('leaveRequestForm');
    const startDateInput = document.getElementById('startDate');
    const endDateInput = document.getElementById('endDate');
    const numberOfDaysInput = document.getElementById('numberOfDays');
    const halfDayRadios = document.querySelectorAll('input[name="half_day"]');
    const messageContainer = document.getElementById('messageContainer');
    const messageContent = document.getElementById('messageContent');

    // Set minimum date to today
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
        endDateInput.min = this.value;
        calculateDays();
    });

    endDateInput.addEventListener('change', calculateDays);

    halfDayRadios.forEach(radio => {
        radio.addEventListener('change', calculateDays);
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

        // Validate future dates
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        if (startDateInput.value) {
            const startDate = new Date(startDateInput.value);
            if (startDate < today) {
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

        // Prepare form data
        const formData = new FormData(form);
        
        // Convert to JSON
        const data = {};
        formData.forEach((value, key) => {
            data[key] = value;
        });

        // Submit via fetch
        fetch('/submit-leave-request', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        })
        .then(response => response.json())
        .then(result => {
            if (result.success) {
                showMessage('Leave request submitted successfully!', 'success');
                form.reset();
                numberOfDaysInput.value = '';
                // Remove validation classes
                form.querySelectorAll('.valid, .invalid').forEach(field => {
                    field.classList.remove('valid', 'invalid');
                });
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
            // Remove all validation classes
            form.querySelectorAll('.valid, .invalid').forEach(field => {
                field.classList.remove('valid', 'invalid');
            });
        }, 10);
    });
});