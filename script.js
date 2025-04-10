document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const emailError = document.getElementById('emailError');
    const passwordError = document.getElementById('passwordError');
    const loginButton = document.querySelector('.login-button');
    const buttonText = document.querySelector('.button-text');
    const spinner = document.querySelector('.spinner');

    // Form validation
    function validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    }

    function validatePassword(password) {
        return password.length >= 6;
    }

    function showError(element, message) {
        element.textContent = message;
        element.style.display = 'block';
    }

    function hideError(element) {
        element.textContent = '';
        element.style.display = 'none';
    }

    function showLoading() {
        buttonText.classList.add('hidden');
        spinner.classList.remove('hidden');
        loginButton.disabled = true;
    }

    function hideLoading() {
        buttonText.classList.remove('hidden');
        spinner.classList.add('hidden');
        loginButton.disabled = false;
    }

    // Input validation
    emailInput.addEventListener('input', () => {
        if (!validateEmail(emailInput.value)) {
            showError(emailError, 'Please enter a valid email address');
        } else {
            hideError(emailError);
        }
    });

    passwordInput.addEventListener('input', () => {
        if (!validatePassword(passwordInput.value)) {
            showError(passwordError, 'Password must be at least 6 characters long');
        } else {
            hideError(passwordError);
        }
    });

    // Form submission
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        // Reset error messages
        hideError(emailError);
        hideError(passwordError);

        // Validate inputs
        let isValid = true;

        if (!validateEmail(emailInput.value)) {
            showError(emailError, 'Please enter a valid email address');
            isValid = false;
        }

        if (!validatePassword(passwordInput.value)) {
            showError(passwordError, 'Password must be at least 6 characters long');
            isValid = false;
        }

        if (!isValid) return;

        // Show loading state
        showLoading();

        try {
            // Simulate API call
            await new Promise(resolve => setTimeout(resolve, 1500));

            // Redirect to home page on successful login
            window.location.href = 'home.html';
        } catch (error) {
            // Handle login error
            showError(emailError, 'Invalid email or password');
            hideLoading();
        }
    });

    // Social login buttons
    const googleButton = document.querySelector('.social-button.google');
    const metamaskButton = document.querySelector('.social-button.metamask');

    googleButton.addEventListener('click', () => {
        // Implement Google login
        console.log('Google login clicked');
    });

    metamaskButton.addEventListener('click', () => {
        // Implement MetaMask login
        console.log('MetaMask login clicked');
    });

    // Mobile menu toggle
    const mobileMenuBtn = document.querySelector('.mobile-menu');
    const navLinks = document.querySelector('.nav-links');

    mobileMenuBtn.addEventListener('click', () => {
        navLinks.style.display = navLinks.style.display === 'flex' ? 'none' : 'flex';
    });

    // Smooth scroll for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // Intersection Observer for fade-in animations
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    // Observe feature cards
    document.querySelectorAll('.feature-card').forEach(card => {
        observer.observe(card);
    });

    // Add animation class to elements when they come into view
    const animateOnScroll = () => {
        const elements = document.querySelectorAll('.feature-card, .about-content');
        elements.forEach(element => {
            const elementTop = element.getBoundingClientRect().top;
            const elementBottom = element.getBoundingClientRect().bottom;
            
            if (elementTop < window.innerHeight && elementBottom > 0) {
                element.classList.add('visible');
            }
        });
    };

    // Initial check
    animateOnScroll();

    // Check on scroll
    window.addEventListener('scroll', animateOnScroll);

    // Handle CTA button click
    const ctaButton = document.querySelector('.cta-button');
    ctaButton.addEventListener('click', () => {
        // Add your desired action here
        console.log('Get Started button clicked');
        // Example: Redirect to registration page
        // window.location.href = '/register';
    });
}); 