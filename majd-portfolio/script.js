/* ================================================================
   Majd Portfolio — Interactive Script
   Handles: scroll reveals, menu, parallax, form, navbar effects
   ================================================================ */

document.addEventListener('DOMContentLoaded', () => {

    // ==============================
    // Intersection Observer — Scroll Reveal
    // ==============================
    const revealObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, {
        threshold: 0.12,
        rootMargin: '0px 0px -40px 0px'
    });

    document.querySelectorAll('.reveal, .stagger').forEach(el => {
        revealObserver.observe(el);
    });

    // ==============================
    // Mobile Menu Toggle
    // ==============================
    const menuToggle = document.getElementById('menu-toggle');
    const mobileMenu = document.getElementById('mobile-menu');
    let menuOpen = false;

    menuToggle.addEventListener('click', () => {
        menuOpen = !menuOpen;
        mobileMenu.classList.toggle('active', menuOpen);
        document.body.style.overflow = menuOpen ? 'hidden' : '';
    });

    // Close menu when a link is clicked
    mobileMenu.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', () => {
            menuOpen = false;
            mobileMenu.classList.remove('active');
            document.body.style.overflow = '';
        });
    });

    // Close menu on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && menuOpen) {
            menuOpen = false;
            mobileMenu.classList.remove('active');
            document.body.style.overflow = '';
        }
    });

    // ==============================
    // Navbar Scroll Effect
    // ==============================
    const navbar = document.getElementById('navbar');
    let ticking = false;

    window.addEventListener('scroll', () => {
        if (!ticking) {
            requestAnimationFrame(() => {
                const scrollY = window.pageYOffset;
                if (scrollY > 100) {
                    navbar.style.boxShadow = '0 4px 30px rgba(0,0,0,0.25)';
                } else {
                    navbar.style.boxShadow = '0 4px 20px rgba(0,0,0,0.15)';
                }
                ticking = false;
            });
            ticking = true;
        }
    });

    // ==============================
    // Smooth Scroll for Anchor Links
    // ==============================
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;

            e.preventDefault();
            const target = document.querySelector(targetId);
            if (target) {
                const offset = 80; // Account for fixed nav
                const targetPosition = target.getBoundingClientRect().top + window.pageYOffset - offset;

                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });

    // ==============================
    // Hero Parallax Effects
    // ==============================
    const heroPortrait = document.querySelector('.hero__portrait');
    const heroStar = document.querySelector('.hero__star');
    const heroSection = document.querySelector('.hero');

    function handleParallax() {
        const scrollY = window.pageYOffset;
        const heroHeight = heroSection ? heroSection.offsetHeight : 800;

        if (scrollY < heroHeight && window.innerWidth > 809) {
            if (heroPortrait) {
                heroPortrait.style.transform =
                    `translate(-50%, calc(-50% + ${scrollY * 0.12}px))`;
            }
            if (heroStar) {
                heroStar.style.animationPlayState = 'running';
            }
        }
    }

    let parallaxTicking = false;
    window.addEventListener('scroll', () => {
        if (!parallaxTicking) {
            requestAnimationFrame(() => {
                handleParallax();
                parallaxTicking = false;
            });
            parallaxTicking = true;
        }
    });

    // ==============================
    // Contact Form Handling
    // ==============================
    const contactForm = document.getElementById('contact-form');
    const submitBtn = document.getElementById('submit-btn');

    if (contactForm) {
        contactForm.addEventListener('submit', (e) => {
            e.preventDefault();

            // Visual feedback
            const originalText = submitBtn.textContent;
            submitBtn.textContent = 'Sending...';
            submitBtn.style.opacity = '0.7';

            // Simulate submission
            setTimeout(() => {
                submitBtn.textContent = '✓ Sent!';
                submitBtn.style.opacity = '1';
                submitBtn.style.background = '#2ecc71';

                setTimeout(() => {
                    submitBtn.textContent = originalText;
                    submitBtn.style.background = '';
                    contactForm.reset();
                }, 2500);
            }, 800);
        });
    }

    // ==============================
    // Service Item Hover Counter
    // ==============================
    const serviceItems = document.querySelectorAll('.services__item');
    serviceItems.forEach((item, index) => {
        const num = String(index + 1).padStart(2, '0');
        item.setAttribute('data-index', num);
    });

});
