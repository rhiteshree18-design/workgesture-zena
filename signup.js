document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('signupForm');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = {
            name: form.name.value,
            email: form.email.value,
            password: form.password.value,
            confirmPassword: form.confirmPassword.value
        };

        try {
            const response = await fetch('http://localhost:3000/signup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(formData)
            });

            const message = await response.text();
            alert(message);

            if (response.ok) {
                form.reset();
                localStorage.setItem("isLoggedIn", "true");
                setTimeout(() => {
                    window.location.href = 'home.html';
                }, 1500);
            }
        } catch (error) {
            console.error('❌ Signup Error:', error);
            alert('Server error. Try again later.');
        }
    });
});
