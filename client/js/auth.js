// Login Form Handler
redirectIfLoggedIn();

const loginForm = document.getElementById('loginForm');
const submitBtn = document.getElementById('submitBtn');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const emailError = document.getElementById('emailError');
const passwordError = document.getElementById('passwordError');

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    // Clear previous errors
    emailError.textContent = '';
    passwordError.textContent = '';
    emailInput.classList.remove('error');
    passwordInput.classList.remove('error');

    const email = emailInput.value.trim();
    const password = passwordInput.value;

    // Simple validation
    if (!email) {
        emailError.textContent = 'Email is required';
        emailInput.classList.add('error');
        return;
    }

    if (!password) {
        passwordError.textContent = 'Password is required';
        passwordInput.classList.add('error');
        return;
    }

    // Disable button and show loading
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner"></span> Signing in...';

    try {
        await login(email, password);
        showToast('Login successful!', 'success');

        // Redirect to dashboard
        setTimeout(() => {
            window.location.href = 'dashboard.html';
        }, 500);
    } catch (error) {
        showToast(error.message || 'Login failed', 'error');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Sign in';
    }
});
