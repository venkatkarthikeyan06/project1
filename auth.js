document.addEventListener('DOMContentLoaded', () => {
    // Handle login form submission
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('login-email').value.trim();
            const password = document.getElementById('login-password').value.trim();

            if (!email || !password) {
                alert('Please fill in all fields.');
                return;
            }

            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password }),
                });

                if (response.ok) {
                    const { token } = await response.json();
                    localStorage.setItem('token', token);
                    // Redirect to personalization.html after successful login
                    window.location.href = '/personalization.html';
                } else {
                    const error = await response.json();
                    alert(`Login unsuccessful: ${error.error || 'Unknown error'}`);
                }
            } catch (err) {
                console.error('Error logging in:', err);
                alert('Login unsuccessful: An error occurred.');
            }
        });
    }

    // Handle register form submission
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = document.getElementById('register-name').value.trim();
            const email = document.getElementById('register-email').value.trim();
            const password = document.getElementById('register-password').value.trim();

            if (!name || !email || !password) {
                alert('Please fill in all fields.');
                return;
            }

            try {
                const response = await fetch('/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, email, password }),
                });

                if (response.ok) {
                    alert('Registration successful! Please log in.');
                    // Optionally clear the form or redirect to login
                    registerForm.reset();
                } else {
                    const error = await response.json();
                    alert(`Registration unsuccessful: ${error.error || 'Unknown error'}`);
                }
            } catch (err) {
                console.error('Error registering:', err);
                alert('Registration unsuccessful: An error occurred.');
            }
        });
    }
});
