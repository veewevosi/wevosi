document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            let isValid = true;
            
            // Clear previous error messages
            form.querySelectorAll('.error-message').forEach(msg => msg.remove());
            
            // Validate email
            const emailInput = form.querySelector('input[type="email"]');
            if (emailInput && !isValidEmail(emailInput.value)) {
                showError(emailInput, 'Please enter a valid email address');
                isValid = false;
            }
            
            // Validate password
            const passwordInput = form.querySelector('input[type="password"]');
            if (passwordInput && passwordInput.value.length < 8) {
                showError(passwordInput, 'Password must be at least 8 characters long');
                isValid = false;
            }
            
            // Validate username if present
            const usernameInput = form.querySelector('input[name="username"]');
            if (usernameInput && usernameInput.value.length < 3) {
                showError(usernameInput, 'Username must be at least 3 characters long');
                isValid = false;
            }
            
            if (!isValid) {
                e.preventDefault();
            }
        });
    });
    
    function isValidEmail(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }
    
    function showError(input, message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.textContent = message;
        input.parentNode.appendChild(errorDiv);
    }
});
