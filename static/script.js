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

    // Mobile Menu Toggle
    const mobileMenuBtn = document.querySelector('.mobile-menu');
    const navLinks = document.querySelector('.nav-links');
    const body = document.body;

    mobileMenuBtn.addEventListener('click', () => {
        navLinks.classList.toggle('active');
        mobileMenuBtn.classList.toggle('active');
        body.classList.toggle('menu-open');
    });

    // Close mobile menu when clicking outside
    document.addEventListener('click', (e) => {
        if (!navLinks.contains(e.target) && !mobileMenuBtn.contains(e.target)) {
            navLinks.classList.remove('active');
            mobileMenuBtn.classList.remove('active');
            body.classList.remove('menu-open');
        }
    });

    // Smooth Scroll with Offset
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                const headerOffset = 80;
                const elementPosition = target.getBoundingClientRect().top;
                const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

                window.scrollTo({
                    top: offsetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });

    // Intersection Observer for Animations
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

    // Observe all animated elements
    document.querySelectorAll('.feature-card, .choose-item, .step, .use-case-card, .tech-card, .info-item, .contact-form').forEach(element => {
        observer.observe(element);
    });

    // Parallax Effect for Hero Section
    const hero = document.querySelector('.hero');
    if (hero) {
        window.addEventListener('scroll', () => {
            const scrolled = window.pageYOffset;
            hero.style.backgroundPositionY = -(scrolled * 0.5) + 'px';
        });
    }

    // Form Validation with Enhanced Feedback
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            const submitButton = form.querySelector('button[type="submit"]');
            const originalText = submitButton.textContent;

            // Show loading state
            submitButton.classList.add('loading');
            submitButton.disabled = true;

            // Simulate form submission
            setTimeout(() => {
                submitButton.classList.remove('loading');
                submitButton.disabled = false;
                submitButton.textContent = 'Success!';
                
                // Reset button text after 2 seconds
                setTimeout(() => {
                    submitButton.textContent = originalText;
                }, 2000);
            }, 1500);
        });
    });

    // Enhanced Hover Effects
    const cards = document.querySelectorAll('.feature-card, .choose-item, .step, .use-case-card, .tech-card');
    cards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.style.transform = 'translateY(-10px) scale(1.02)';
        });
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'translateY(0) scale(1)';
        });
    });

    // Dynamic Header Background
    const header = document.querySelector('.header');
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            header.style.background = 'rgba(255, 255, 255, 0.95)';
            header.style.boxShadow = '0 2px 10px rgba(0, 0, 0, 0.1)';
        } else {
            header.style.background = 'transparent';
            header.style.boxShadow = 'none';
        }
    });

    // Theme Toggle Functionality
    const themeToggle = document.querySelector('.theme-toggle');
    const themeIcon = themeToggle.querySelector('i');
    
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);

    themeToggle.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeIcon(newTheme);
    });

    function updateThemeIcon(theme) {
        themeIcon.className = theme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
    }

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