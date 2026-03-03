<?php
/**
 * =============================================================================
 * DIGITAL IDENTITY PORTAL - REGISTRATION MODULE
 * =============================================================================
 * 
 * File: index.php
 * Purpose: Secure attendee registration form with client-side validation
 * 
 * ARCHITECTURE NOTES:
 * -------------------
 * This file implements the "C" (Client) side of our Client-Server handshake.
 * The form's `action` attribute points to profile.php, and the `method="POST"`
 * ensures sensitive data travels in the HTTP request BODY, not the URL.
 * 
 * WHY POST AND NOT GET?
 * ---------------------
 * GET requests encode data in the URL: /profile.php?username=John&job=Developer
 * 
 * Problems with GET for sensitive/profile data:
 * 1. URLs are logged in server access logs, browser history, and proxy caches
 * 2. URLs can be shoulder-surfed or leaked via the Referer header
 * 3. URLs have length limits (~2048 chars) - unsuitable for large payloads
 * 4. GET implies idempotency (safe to repeat) - registration is NOT idempotent
 * 
 * POST requests:
 * 1. Data travels in the request BODY - not visible in logs or history
 * 2. No length restrictions (server-configurable via php.ini)
 * 3. Semantically correct for "create" operations (REST principles)
 * 4. Required for any operation that modifies server state
 * 
 * DEFENSIVE PROGRAMMING MINDSET:
 * ------------------------------
 * We assume every user is potentially:
 * - A bot trying to flood our server with garbage requests
 * - A penetration tester probing for XSS/SQLi vulnerabilities
 * - A legitimate user with a broken browser or slow connection
 * 
 * Client-side validation is our FIRST LINE OF DEFENSE - it reduces server load
 * by rejecting obviously invalid requests before they hit the network.
 * 
 * CRITICAL: Client-side validation is a UX feature, NOT a security feature.
 * It can be bypassed with curl, Postman, or browser DevTools.
 * Server-side validation in profile.php is MANDATORY.
 * 
 * @author Senior Principal Engineer
 * @version 1.0.0
 * @security-review 2026-03-03
 */

// OPTIONAL: Session-based CSRF token generation for enhanced security
// In production, you'd generate and validate a CSRF token here
// session_start();
// $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>
<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Digital Identity Portal - Register for the Tech Conference">
    
    <!-- Security Headers via meta tags (complement server-side headers) -->
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    
    <title>Digital Identity Portal | Registration</title>
    
    <!-- Tailwind CSS via CDN (for demo - in production, use a local build) -->
    <script src="https://cdn.tailwindcss.com"></script>
    
    <!-- Custom Tailwind Configuration for Tech Conference Aesthetic -->
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        // Custom palette: Cyber-noir with electric accents
                        'cyber': {
                            900: '#0a0a0f',
                            800: '#12121a',
                            700: '#1a1a24',
                            600: '#22222e',
                            500: '#2a2a38',
                        },
                        'electric': {
                            400: '#00d4ff',
                            500: '#00b8e6',
                            600: '#009dcc',
                        },
                        'neon': {
                            purple: '#a855f7',
                            pink: '#ec4899',
                        }
                    },
                    fontFamily: {
                        'mono': ['JetBrains Mono', 'Fira Code', 'monospace'],
                    },
                    animation: {
                        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                        'gradient': 'gradient 8s ease infinite',
                    },
                    keyframes: {
                        gradient: {
                            '0%, 100%': { backgroundPosition: '0% 50%' },
                            '50%': { backgroundPosition: '100% 50%' },
                        }
                    }
                }
            }
        }
    </script>
    
    <style>
        /* Custom gradient animation for the card border */
        .gradient-border {
            background: linear-gradient(135deg, #00d4ff, #a855f7, #ec4899, #00d4ff);
            background-size: 300% 300%;
            animation: gradient 8s ease infinite;
        }
        
        /* Subtle glow effect on focus */
        .input-glow:focus {
            box-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
        }
        
        /* Custom scrollbar for dark mode */
        ::-webkit-scrollbar {
            width: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #12121a;
        }
        ::-webkit-scrollbar-thumb {
            background: #2a2a38;
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #00d4ff;
        }
    </style>
</head>

<body class="min-h-screen bg-cyber-900 text-gray-100 font-sans antialiased">
    
    <!-- Background Pattern: Subtle grid for tech aesthetic -->
    <div class="fixed inset-0 bg-[linear-gradient(rgba(0,212,255,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,212,255,0.03)_1px,transparent_1px)] bg-[size:50px_50px] pointer-events-none"></div>
    
    <!-- Main Container -->
    <main class="relative z-10 flex items-center justify-center min-h-screen px-4 py-12">
        
        <div class="w-full max-w-md">
            
            <!-- Header Section -->
            <header class="text-center mb-8">
                <!-- Logo/Icon -->
                <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-electric-400 to-neon-purple mb-4 shadow-lg shadow-electric-400/20">
                    <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2"></path>
                    </svg>
                </div>
                
                <h1 class="text-3xl font-bold bg-gradient-to-r from-electric-400 via-neon-purple to-neon-pink bg-clip-text text-transparent">
                    Digital Identity Portal
                </h1>
                <p class="mt-2 text-gray-400">
                    Register for <span class="text-electric-400 font-semibold">TechConf 2026</span>
                </p>
            </header>
            
            <!-- Registration Card with Animated Border -->
            <div class="gradient-border p-[2px] rounded-2xl">
                <div class="bg-cyber-800 rounded-2xl p-8">
                    
                    <!--
                    =================================================================
                    THE ANATOMY OF A REQUEST
                    =================================================================
                    
                    When this form is submitted:
                    
                    1. Browser collects values from inputs with `name` attributes
                    2. Data is encoded as: username=value&job_title=value&fav_lang=value
                    3. HTTP POST request is constructed with body containing this data
                    4. Request travels to profile.php (specified in `action`)
                    5. PHP parses the body and populates $_POST superglobal:
                       $_POST = [
                           'username' => 'submitted_value',
                           'job_title' => 'submitted_value',
                           'fav_lang' => 'submitted_value'
                       ];
                    
                    The `name` attribute is the KEY. No name = no data transmission.
                    The `id` attribute is for DOM manipulation only (labels, JS).
                    
                    =================================================================
                    -->
                    
                    <form 
                        action="profile.php" 
                        method="POST"
                        class="space-y-6"
                        id="registrationForm"
                        novalidate
                    >
                        <!-- 
                        NOTE: We use novalidate + custom JS validation for UX control.
                        The required/minlength attributes still work as fallback.
                        -->
                        
                        <!-- Username Field -->
                        <div class="space-y-2">
                            <label 
                                for="username" 
                                class="block text-sm font-medium text-gray-300"
                            >
                                Username
                                <span class="text-neon-pink">*</span>
                            </label>
                            <div class="relative">
                                <span class="absolute inset-y-0 left-0 flex items-center pl-4 text-gray-500">
                                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
                                    </svg>
                                </span>
                                <input 
                                    type="text" 
                                    id="username" 
                                    name="username"
                                    required
                                    minlength="3"
                                    maxlength="50"
                                    autocomplete="username"
                                    placeholder="e.g., cyber_pioneer"
                                    aria-describedby="username-hint"
                                    class="input-glow w-full pl-12 pr-4 py-3 bg-cyber-700 border border-cyber-500 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:border-electric-400 transition-all duration-300"
                                >
                            </div>
                            <p id="username-hint" class="text-xs text-gray-500">
                                3-50 characters. This will appear on your badge.
                            </p>
                        </div>
                        
                        <!-- Job Title Field -->
                        <div class="space-y-2">
                            <label 
                                for="job_title" 
                                class="block text-sm font-medium text-gray-300"
                            >
                                Job Title
                                <span class="text-neon-pink">*</span>
                            </label>
                            <div class="relative">
                                <span class="absolute inset-y-0 left-0 flex items-center pl-4 text-gray-500">
                                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 13.255A23.931 23.931 0 0112 15c-3.183 0-6.22-.62-9-1.745M16 6V4a2 2 0 00-2-2h-4a2 2 0 00-2 2v2m4 6h.01M5 20h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                                    </svg>
                                </span>
                                <input 
                                    type="text" 
                                    id="job_title" 
                                    name="job_title"
                                    required
                                    minlength="2"
                                    maxlength="100"
                                    autocomplete="organization-title"
                                    placeholder="e.g., Senior Software Architect"
                                    aria-describedby="job-hint"
                                    class="input-glow w-full pl-12 pr-4 py-3 bg-cyber-700 border border-cyber-500 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:border-electric-400 transition-all duration-300"
                                >
                            </div>
                            <p id="job-hint" class="text-xs text-gray-500">
                                Your professional title for networking.
                            </p>
                        </div>
                        
                        <!-- Favorite Language (Select for controlled input) -->
                        <div class="space-y-2">
                            <label 
                                for="fav_lang" 
                                class="block text-sm font-medium text-gray-300"
                            >
                                Favorite Programming Language
                                <span class="text-neon-pink">*</span>
                            </label>
                            <div class="relative">
                                <span class="absolute inset-y-0 left-0 flex items-center pl-4 text-gray-500 pointer-events-none">
                                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                                    </svg>
                                </span>
                                <select 
                                    id="fav_lang" 
                                    name="fav_lang"
                                    required
                                    aria-describedby="lang-hint"
                                    class="input-glow w-full pl-12 pr-10 py-3 bg-cyber-700 border border-cyber-500 rounded-lg text-gray-100 focus:outline-none focus:border-electric-400 transition-all duration-300 appearance-none cursor-pointer"
                                >
                                    <option value="" disabled selected>Choose your weapon...</option>
                                    <option value="PHP">PHP</option>
                                    <option value="JavaScript">JavaScript</option>
                                    <option value="TypeScript">TypeScript</option>
                                    <option value="Python">Python</option>
                                    <option value="Go">Go</option>
                                    <option value="Rust">Rust</option>
                                    <option value="Java">Java</option>
                                    <option value="C#">C#</option>
                                    <option value="C++">C++</option>
                                    <option value="Ruby">Ruby</option>
                                    <option value="Swift">Swift</option>
                                    <option value="Kotlin">Kotlin</option>
                                </select>
                                <!-- Custom dropdown arrow -->
                                <span class="absolute inset-y-0 right-0 flex items-center pr-4 text-gray-500 pointer-events-none">
                                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                                    </svg>
                                </span>
                            </div>
                            <p id="lang-hint" class="text-xs text-gray-500">
                                For badge customization and networking matches.
                            </p>
                        </div>
                        
                        <!-- Submit Button -->
                        <button 
                            type="submit"
                            class="group relative w-full py-4 px-6 bg-gradient-to-r from-electric-500 to-neon-purple text-white font-bold rounded-lg overflow-hidden transition-all duration-300 hover:shadow-lg hover:shadow-electric-400/30 hover:scale-[1.02] focus:outline-none focus:ring-2 focus:ring-electric-400 focus:ring-offset-2 focus:ring-offset-cyber-800 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            <!-- Button shine effect -->
                            <span class="absolute inset-0 w-full h-full bg-gradient-to-r from-transparent via-white/20 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-700"></span>
                            
                            <span class="relative flex items-center justify-center gap-2">
                                <span>Generate My Badge</span>
                                <svg class="w-5 h-5 group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6"></path>
                                </svg>
                            </span>
                        </button>
                        
                    </form>
                    
                    <!-- Form validation error container -->
                    <div id="error-container" class="hidden mt-4 p-4 bg-red-900/30 border border-red-500/50 rounded-lg">
                        <p class="text-red-400 text-sm flex items-center gap-2">
                            <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                            <span id="error-message"></span>
                        </p>
                    </div>
                    
                </div>
            </div>
            
            <!-- Footer -->
            <footer class="mt-8 text-center text-xs text-gray-600">
                <p>Your data is transmitted securely via HTTPS POST.</p>
                <p class="mt-1">
                    <span class="text-electric-400">TechConf 2026</span> • 
                    <span class="text-gray-500">Security-First Architecture</span>
                </p>
            </footer>
            
        </div>
    </main>
    
    <!--
    =================================================================
    CLIENT-SIDE VALIDATION SCRIPT
    =================================================================
    
    PURPOSE: Prevent "garbage" hits to the server. This improves UX by
    providing instant feedback and reduces server load.
    
    REMINDER: This is NOT a security measure. Any determined attacker
    can bypass this with curl:
    
        curl -X POST -d "username=<script>alert('XSS')</script>" profile.php
    
    Server-side validation in profile.php is the TRUE security layer.
    
    =================================================================
    -->
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const form = document.getElementById('registrationForm');
            const errorContainer = document.getElementById('error-container');
            const errorMessage = document.getElementById('error-message');
            
            // Input elements
            const usernameInput = document.getElementById('username');
            const jobTitleInput = document.getElementById('job_title');
            const favLangSelect = document.getElementById('fav_lang');
            
            /**
             * Display validation error with animation
             */
            function showError(message) {
                errorMessage.textContent = message;
                errorContainer.classList.remove('hidden');
                errorContainer.classList.add('animate-pulse');
                
                // Remove animation after it plays
                setTimeout(() => {
                    errorContainer.classList.remove('animate-pulse');
                }, 1000);
            }
            
            /**
             * Hide error container
             */
            function hideError() {
                errorContainer.classList.add('hidden');
            }
            
            /**
             * Validate form before submission
             */
            form.addEventListener('submit', (event) => {
                hideError();
                
                const username = usernameInput.value.trim();
                const jobTitle = jobTitleInput.value.trim();
                const favLang = favLangSelect.value;
                
                // Username validation
                if (!username) {
                    event.preventDefault();
                    showError('Username is required.');
                    usernameInput.focus();
                    return;
                }
                
                if (username.length < 3) {
                    event.preventDefault();
                    showError('Username must be at least 3 characters.');
                    usernameInput.focus();
                    return;
                }
                
                // Job title validation
                if (!jobTitle) {
                    event.preventDefault();
                    showError('Job title is required.');
                    jobTitleInput.focus();
                    return;
                }
                
                if (jobTitle.length < 2) {
                    event.preventDefault();
                    showError('Job title must be at least 2 characters.');
                    jobTitleInput.focus();
                    return;
                }
                
                // Language validation
                if (!favLang) {
                    event.preventDefault();
                    showError('Please select your favorite programming language.');
                    favLangSelect.focus();
                    return;
                }
                
                // All validations passed - form will submit naturally
                // Show loading state
                const submitButton = form.querySelector('button[type="submit"]');
                submitButton.disabled = true;
                submitButton.innerHTML = `
                    <span class="flex items-center justify-center gap-2">
                        <svg class="animate-spin w-5 h-5" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        <span>Processing...</span>
                    </span>
                `;
            });
            
            // Real-time input validation feedback
            [usernameInput, jobTitleInput].forEach(input => {
                input.addEventListener('input', () => {
                    hideError();
                    
                    if (input.validity.valid) {
                        input.classList.remove('border-red-500');
                        input.classList.add('border-green-500');
                    } else {
                        input.classList.remove('border-green-500', 'border-cyber-500');
                        if (input.value.length > 0) {
                            input.classList.add('border-red-500');
                        }
                    }
                });
                
                input.addEventListener('blur', () => {
                    if (!input.value) {
                        input.classList.remove('border-green-500', 'border-red-500');
                        input.classList.add('border-cyber-500');
                    }
                });
            });
            
            // Select change feedback
            favLangSelect.addEventListener('change', () => {
                hideError();
                if (favLangSelect.value) {
                    favLangSelect.classList.remove('border-cyber-500');
                    favLangSelect.classList.add('border-green-500');
                }
            });
        });
    </script>
    
</body>
</html>
