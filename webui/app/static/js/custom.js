// Custom JavaScript for FreeRADIUS TOTP Management System

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Flash message auto-dismiss
    setTimeout(function() {
        var flashMessages = document.querySelectorAll('.alert:not(.alert-warning):not(.alert-danger)');
        flashMessages.forEach(function(message) {
            var alert = new bootstrap.Alert(message);
            alert.close();
        });
    }, 5000);
    
    // Password strength meter
    var passwordInputs = document.querySelectorAll('input[type="password"]:not([id="current_password"])');
    passwordInputs.forEach(function(input) {
        input.addEventListener('input', function() {
            var password = this.value;
            var strength = 0;
            
            // Create strength meter if it doesn't exist
            var meterId = this.id + '-strength';
            var meter = document.getElementById(meterId);
            
            if (!meter) {
                meter = document.createElement('div');
                meter.id = meterId;
                meter.className = 'progress mt-2';
                meter.innerHTML = '<div class="progress-bar" role="progressbar" style="width: 0%"></div>';
                this.parentNode.appendChild(meter);
            }
            
            var progressBar = meter.querySelector('.progress-bar');
            
            // Check password strength
            if (password.length >= 8) strength += 20;
            if (password.match(/[a-z]+/)) strength += 20;
            if (password.match(/[A-Z]+/)) strength += 20;
            if (password.match(/[0-9]+/)) strength += 20;
            if (password.match(/[^a-zA-Z0-9]+/)) strength += 20;
            
            // Update progress bar
            progressBar.style.width = strength + '%';
            
            // Update color based on strength
            if (strength < 40) {
                progressBar.className = 'progress-bar bg-danger';
                progressBar.textContent = 'Weak';
            } else if (strength < 80) {
                progressBar.className = 'progress-bar bg-warning';
                progressBar.textContent = 'Medium';
            } else {
                progressBar.className = 'progress-bar bg-success';
                progressBar.textContent = 'Strong';
            }
        });
    });
    
    // Confirm password validation
    var passwordForms = document.querySelectorAll('form:has(input[type="password"])');
    passwordForms.forEach(function(form) {
        form.addEventListener('submit', function(event) {
            var password = form.querySelector('input[id$="password"]');
            var confirmPassword = form.querySelector('input[id$="confirm_password"]');
            
            if (password && confirmPassword && password.value !== confirmPassword.value) {
                event.preventDefault();
                alert('Passwords do not match!');
            }
        });
    });
    
    // Copy to clipboard functionality
    var copyButtons = document.querySelectorAll('.btn-copy');
    copyButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            var textToCopy = this.getAttribute('data-copy');
            var tempInput = document.createElement('input');
            tempInput.value = textToCopy;
            document.body.appendChild(tempInput);
            tempInput.select();
            document.execCommand('copy');
            document.body.removeChild(tempInput);
            
            // Show copied message
            var originalText = this.innerHTML;
            this.innerHTML = '<i class="fas fa-check"></i> Copied!';
            setTimeout(function() {
                button.innerHTML = originalText;
            }, 2000);
        });
    });
    
    // TOTP token input formatting
    var totpInputs = document.querySelectorAll('input[id="token"]');
    totpInputs.forEach(function(input) {
        input.addEventListener('input', function() {
            // Remove non-digits
            this.value = this.value.replace(/\D/g, '');
            
            // Limit to 6 digits
            if (this.value.length > 6) {
                this.value = this.value.slice(0, 6);
            }
        });
    });
    
    // Auto-submit TOTP form when 6 digits are entered
    var totpForms = document.querySelectorAll('form:has(input[id="token"])');
    totpForms.forEach(function(form) {
        var input = form.querySelector('input[id="token"]');
        if (input) {
            input.addEventListener('input', function() {
                if (this.value.length === 6) {
                    form.submit();
                }
            });
        }
    });
    
    // Search form auto-submit after delay
    var searchInputs = document.querySelectorAll('input[type="search"], input[name="search"], input[name="query"]');
    searchInputs.forEach(function(input) {
        var timeout = null;
        input.addEventListener('input', function() {
            clearTimeout(timeout);
            timeout = setTimeout(function() {
                input.closest('form').submit();
            }, 500);
        });
    });
    
    // Confirm dangerous actions
    var dangerousForms = document.querySelectorAll('form:has(button.btn-danger)');
    dangerousForms.forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!confirm('Are you sure you want to perform this action? This cannot be undone.')) {
                event.preventDefault();
            }
        });
    });
    
    // Add fade-in animation to cards
    var cards = document.querySelectorAll('.card');
    cards.forEach(function(card, index) {
        setTimeout(function() {
            card.classList.add('fade-in');
        }, index * 100);
    });
});