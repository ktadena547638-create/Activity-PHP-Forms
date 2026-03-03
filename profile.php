<?php
/**
 * =============================================================================
 * DIGITAL IDENTITY PORTAL - PROFILE RENDERER
 * =============================================================================
 * 
 * File: profile.php
 * Purpose: Server-side validation, POST enforcement, and secure badge rendering
 * 
 * =============================================================================
 * DEFENSIVE PROGRAMMING: THE GUARD CLAUSE PATTERN
 * =============================================================================
 * 
 * A "Guard Clause" is an early-return pattern that validates prerequisites
 * BEFORE executing main logic. It's the architectural equivalent of a bouncer
 * checking IDs before letting anyone into the club.
 * 
 * Why Guard Clauses?
 * 1. FAIL FAST: Reject invalid requests immediately
 * 2. REDUCE NESTING: Avoids deeply nested if/else pyramids
 * 3. CLEAR INTENT: The first thing you see is "what can go wrong"
 * 4. SINGLE RESPONSIBILITY: Validation is separate from business logic
 * 
 * =============================================================================
 * WHY WE ASSUME THE USER IS MALICIOUS
 * =============================================================================
 * 
 * In security, we follow the "Zero Trust" principle:
 * - NEVER trust client input (it can be spoofed with curl, Postman, etc.)
 * - ALWAYS validate on the server (client validation is a UX courtesy)
 * - ALWAYS encode output (the database might be compromised)
 * 
 * Attack vectors we defend against here:
 * 1. Direct GET access (someone bookmarks/shares the URL)
 * 2. XSS injection via username/job_title (e.g., <script>alert('XSS')</script>)
 * 3. Missing POST keys (malformed requests)
 * 4. Empty values (bypassed client validation)
 * 
 * =============================================================================
 * PRO-TIP: filter_input() vs. Direct $_POST Access
 * =============================================================================
 * 
 * PRODUCTION RECOMMENDATION: Use filter_input() instead of direct array access.
 * 
 * Direct access ($_POST['username']):
 * - Returns the raw value as-is
 * - Throws E_NOTICE if key doesn't exist (unless you use ?? null)
 * - No type coercion or sanitization
 * 
 * filter_input(INPUT_POST, 'username', FILTER_SANITIZE_SPECIAL_CHARS):
 * - Returns null if key doesn't exist (no notices)
 * - Returns false if filter fails
 * - Applies sanitization/validation filters automatically
 * - Type-safe (FILTER_VALIDATE_INT, FILTER_VALIDATE_EMAIL, etc.)
 * - Explicitly documents expected input type in code
 * 
 * Example:
 *   // Production-grade input handling
 *   $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
 *   if ($email === false || $email === null) {
 *       // Handle invalid/missing email
 *   }
 * 
 * For this demo, we use null coalescing + htmlspecialchars for explicitness.
 * 
 * @author Senior Principal Engineer
 * @version 1.0.0
 * @security-review 2026-03-03
 */

// =============================================================================
// CONFIGURATION: Strict error reporting for development
// =============================================================================
declare(strict_types=1);
error_reporting(E_ALL);
// In production: ini_set('display_errors', '0'); and log errors instead

// =============================================================================
// GUARD CLAUSE #1: HTTP Method Enforcement
// =============================================================================
// This page ONLY accepts POST requests. Any other method is either:
// - A direct URL access (someone typed it in or bookmarked it)
// - A search engine crawler trying to index it
// - A malicious probe testing for vulnerabilities
// 
// We respond with HTTP 403 (Forbidden) to clearly signal: "Access Denied"
// Alternatively, you could redirect to index.php with a flash message.

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    
    // Option A: Hard 403 Forbidden (more secure, explicit rejection)
    http_response_code(403);
    
    // Exit early - but provide a styled error page for UX
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>403 Forbidden | Digital Identity Portal</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="min-h-screen bg-gray-900 flex items-center justify-center px-4">
        <div class="text-center">
            <div class="inline-flex items-center justify-center w-20 h-20 rounded-full bg-red-900/30 mb-6">
                <svg class="w-10 h-10 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                </svg>
            </div>
            <h1 class="text-4xl font-bold text-white mb-2">403</h1>
            <p class="text-xl text-red-400 mb-4">Access Forbidden</p>
            <p class="text-gray-400 mb-8 max-w-md">
                This page requires a valid form submission. 
                Direct access is not permitted.
            </p>
            <a 
                href="index.php" 
                class="inline-flex items-center gap-2 px-6 py-3 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded-lg transition-colors"
            >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
                </svg>
                Return to Registration
            </a>
        </div>
    </body>
    </html>
    <?php
    exit; // CRITICAL: Stop execution after the guard clause
    
    // Option B: Silent redirect (less explicit, but smoother UX)
    // header('Location: index.php');
    // exit;
}

// =============================================================================
// DATA EXTRACTION: Using Null Coalescing Operators
// =============================================================================
// The ?? operator returns the left operand if it exists and is not null,
// otherwise it returns the right operand.
// 
// This prevents:
// - "Undefined array key" notices
// - Crashes from malformed requests missing expected keys
// 
// Pattern: $variable = $_POST['key'] ?? 'default_value';

$username = $_POST['username'] ?? '';
$jobTitle = $_POST['job_title'] ?? '';
$favLang  = $_POST['fav_lang'] ?? '';

// =============================================================================
// GUARD CLAUSE #2: Server-Side Validation
// =============================================================================
// Even though we validate on the client, we MUST validate again here.
// Client validation can be bypassed with:
//   curl -X POST -d "username=&job_title=&fav_lang=" http://localhost/profile.php

$errors = [];

// Trim whitespace (attackers might send "   " which passes !empty check)
$username = trim($username);
$jobTitle = trim($jobTitle);
$favLang  = trim($favLang);

// Validate username
if (empty($username)) {
    $errors[] = 'Username is required.';
} elseif (mb_strlen($username) < 3) {
    $errors[] = 'Username must be at least 3 characters.';
} elseif (mb_strlen($username) > 50) {
    $errors[] = 'Username cannot exceed 50 characters.';
}

// Validate job title
if (empty($jobTitle)) {
    $errors[] = 'Job title is required.';
} elseif (mb_strlen($jobTitle) < 2) {
    $errors[] = 'Job title must be at least 2 characters.';
} elseif (mb_strlen($jobTitle) > 100) {
    $errors[] = 'Job title cannot exceed 100 characters.';
}

// Validate favorite language (whitelist approach - more secure than blacklist)
$allowedLanguages = [
    'PHP', 'JavaScript', 'TypeScript', 'Python', 'Go', 
    'Rust', 'Java', 'C#', 'C++', 'Ruby', 'Swift', 'Kotlin'
];

if (empty($favLang)) {
    $errors[] = 'Favorite programming language is required.';
} elseif (!in_array($favLang, $allowedLanguages, true)) {
    // strict comparison (true) prevents type coercion attacks
    $errors[] = 'Invalid programming language selection.';
}

// If validation fails, redirect back with error indication
// In production, you'd use sessions to pass error messages
if (!empty($errors)) {
    http_response_code(400); // Bad Request
    // For now, show errors on this page. Production would use PRG + sessions.
}

// =============================================================================
// OUTPUT ENCODING: XSS NEUTRALIZATION WITH htmlspecialchars()
// =============================================================================
// 
// htmlspecialchars() converts special HTML characters to their entity equivalents:
//   < becomes &lt;
//   > becomes &gt;
//   " becomes &quot;
//   ' becomes &#039; (with ENT_QUOTES flag)
//   & becomes &amp;
// 
// This neutralizes XSS because:
//   <script>alert('XSS')</script>
// becomes:
//   &lt;script&gt;alert('XSS')&lt;/script&gt;
// 
// Which renders as literal text, not executable JavaScript.
// 
// CRITICAL FLAGS:
// - ENT_QUOTES: Encode both double AND single quotes (prevents attribute injection)
// - 'UTF-8': Match your document encoding (prevents encoding-based bypasses)
// - double_encode: false prevents &amp;amp; on already-encoded strings

/**
 * Secure output helper function
 * Wraps htmlspecialchars with secure defaults
 */
function e(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8', false);
}

// Pre-encode values for output (do this ONCE, use everywhere)
$safeUsername = e($username);
$safeJobTitle = e($jobTitle);
$safeFavLang  = e($favLang);

// Generate a pseudo-unique badge ID for visual effect
$badgeId = strtoupper(substr(md5($username . $jobTitle . time()), 0, 8));

// Language-specific styling (for visual flair on the badge)
$langStyles = [
    'PHP'        => ['bg' => 'from-indigo-500 to-purple-600', 'icon' => '🐘'],
    'JavaScript' => ['bg' => 'from-yellow-400 to-yellow-600', 'icon' => '⚡'],
    'TypeScript' => ['bg' => 'from-blue-500 to-blue-700', 'icon' => '📘'],
    'Python'     => ['bg' => 'from-green-400 to-blue-500', 'icon' => '🐍'],
    'Go'         => ['bg' => 'from-cyan-400 to-cyan-600', 'icon' => '🏃'],
    'Rust'       => ['bg' => 'from-orange-500 to-red-600', 'icon' => '🦀'],
    'Java'       => ['bg' => 'from-red-500 to-orange-500', 'icon' => '☕'],
    'C#'         => ['bg' => 'from-purple-500 to-violet-600', 'icon' => '🎯'],
    'C++'        => ['bg' => 'from-blue-600 to-blue-800', 'icon' => '⚙️'],
    'Ruby'       => ['bg' => 'from-red-600 to-red-800', 'icon' => '💎'],
    'Swift'      => ['bg' => 'from-orange-400 to-red-500', 'icon' => '🕊️'],
    'Kotlin'     => ['bg' => 'from-purple-400 to-orange-400', 'icon' => '🎨'],
];

$currentLangStyle = $langStyles[$favLang] ?? ['bg' => 'from-gray-500 to-gray-700', 'icon' => '💻'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow"> <!-- Don't index profile pages -->
    
    <title>Badge Generated | Digital Identity Portal</title>
    
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        'cyber': {
                            900: '#0a0a0f',
                            800: '#12121a',
                            700: '#1a1a24',
                            600: '#22222e',
                        },
                    },
                    animation: {
                        'float': 'float 6s ease-in-out infinite',
                        'shimmer': 'shimmer 2s linear infinite',
                    },
                    keyframes: {
                        float: {
                            '0%, 100%': { transform: 'translateY(0)' },
                            '50%': { transform: 'translateY(-10px)' },
                        },
                        shimmer: {
                            '0%': { backgroundPosition: '-200% 0' },
                            '100%': { backgroundPosition: '200% 0' },
                        }
                    }
                }
            }
        }
    </script>
    <style>
        .badge-holographic {
            background: linear-gradient(
                135deg,
                rgba(255,255,255,0.1) 0%,
                rgba(255,255,255,0.05) 50%,
                rgba(255,255,255,0.1) 100%
            );
            backdrop-filter: blur(10px);
        }
        
        .badge-shine {
            background: linear-gradient(
                90deg,
                transparent 0%,
                rgba(255,255,255,0.2) 50%,
                transparent 100%
            );
            background-size: 200% 100%;
            animation: shimmer 3s infinite;
        }
        
        .badge-border {
            background: conic-gradient(
                from 0deg,
                #00d4ff,
                #a855f7,
                #ec4899,
                #00d4ff
            );
        }
        
        @media print {
            body { background: white !important; }
            .no-print { display: none !important; }
        }
    </style>
</head>

<body class="min-h-screen bg-cyber-900 text-gray-100">
    
    <!-- Background grid -->
    <div class="fixed inset-0 bg-[linear-gradient(rgba(0,212,255,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,212,255,0.03)_1px,transparent_1px)] bg-[size:50px_50px] pointer-events-none"></div>
    
    <main class="relative z-10 flex items-center justify-center min-h-screen px-4 py-12">
        
        <div class="w-full max-w-lg">
            
            <?php if (!empty($errors)): ?>
            <!-- ============================================================= -->
            <!-- VALIDATION ERROR STATE -->
            <!-- ============================================================= -->
            <div class="bg-red-900/30 border border-red-500/50 rounded-2xl p-8 text-center">
                <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-900/50 mb-4">
                    <svg class="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </div>
                
                <h1 class="text-2xl font-bold text-red-400 mb-4">Validation Failed</h1>
                
                <ul class="text-left text-red-300 mb-6 space-y-2">
                    <?php foreach ($errors as $error): ?>
                    <li class="flex items-center gap-2">
                        <svg class="w-4 h-4 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
                        </svg>
                        <!-- 
                        NOTE: $error comes from our hardcoded array, not user input.
                        Still, a paranoid engineer uses e() on everything. 
                        -->
                        <?php echo e($error); ?>
                    </li>
                    <?php endforeach; ?>
                </ul>
                
                <a 
                    href="index.php" 
                    class="inline-flex items-center gap-2 px-6 py-3 bg-red-600 hover:bg-red-500 text-white font-semibold rounded-lg transition-colors"
                >
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
                    </svg>
                    Try Again
                </a>
            </div>
            
            <?php else: ?>
            <!-- ============================================================= -->
            <!-- SUCCESS STATE: CONFERENCE BADGE -->
            <!-- ============================================================= -->
            
            <!-- Success Header -->
            <div class="text-center mb-8">
                <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-green-900/30 border border-green-500/50 mb-4">
                    <svg class="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                    </svg>
                </div>
                <h1 class="text-3xl font-bold text-white mb-2">Registration Complete!</h1>
                <p class="text-gray-400">Your digital badge has been generated.</p>
            </div>
            
            <!-- THE BADGE: Conference-style physical badge aesthetic -->
            <div class="animate-float">
                
                <!-- Outer animated border -->
                <div class="badge-border p-[3px] rounded-3xl shadow-2xl shadow-purple-500/20">
                    
                    <!-- Badge container with holographic effect -->
                    <div class="badge-holographic bg-cyber-800 rounded-3xl overflow-hidden relative">
                        
                        <!-- Shine overlay -->
                        <div class="badge-shine absolute inset-0 pointer-events-none"></div>
                        
                        <!-- Badge Header (language-themed) -->
                        <div class="bg-gradient-to-r <?php echo $currentLangStyle['bg']; ?> px-8 py-6 relative overflow-hidden">
                            
                            <!-- Geometric pattern -->
                            <div class="absolute inset-0 opacity-10">
                                <svg class="w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
                                    <pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse">
                                        <path d="M 10 0 L 0 0 0 10" fill="none" stroke="white" stroke-width="0.5"/>
                                    </pattern>
                                    <rect width="100%" height="100%" fill="url(#grid)"/>
                                </svg>
                            </div>
                            
                            <div class="relative flex items-center justify-between">
                                <div>
                                    <p class="text-white/80 text-sm font-medium tracking-wider uppercase">TechConf 2026</p>
                                    <p class="text-white text-xs mt-1">Attendee Badge</p>
                                </div>
                                <div class="text-4xl"><?php echo $currentLangStyle['icon']; ?></div>
                            </div>
                        </div>
                        
                        <!-- Badge Body -->
                        <div class="px-8 py-8">
                            
                            <!-- Avatar & Name Section -->
                            <div class="flex items-center gap-6 mb-6">
                                <!-- Generated Avatar (initials) -->
                                <div class="w-20 h-20 rounded-2xl bg-gradient-to-br <?php echo $currentLangStyle['bg']; ?> flex items-center justify-center shadow-lg">
                                    <span class="text-2xl font-bold text-white">
                                        <?php 
                                        // Generate initials from username (first two chars, uppercase)
                                        echo e(strtoupper(mb_substr($username, 0, 2)));
                                        ?>
                                    </span>
                                </div>
                                
                                <div class="flex-1">
                                    <!-- 
                                    SECURITY: $safeUsername is already htmlspecialchars'd above.
                                    This prevents: <script>alert('XSS')</script> from executing.
                                    -->
                                    <h2 class="text-2xl font-bold text-white mb-1">
                                        <?php echo $safeUsername; ?>
                                    </h2>
                                    <p class="text-gray-400">
                                        <?php echo $safeJobTitle; ?>
                                    </p>
                                </div>
                            </div>
                            
                            <!-- Info Grid -->
                            <div class="grid grid-cols-2 gap-4 mb-6">
                                
                                <!-- Language Badge -->
                                <div class="bg-cyber-700 rounded-xl p-4">
                                    <p class="text-gray-500 text-xs uppercase tracking-wider mb-1">Primary Language</p>
                                    <p class="text-white font-semibold flex items-center gap-2">
                                        <span class="text-lg"><?php echo $currentLangStyle['icon']; ?></span>
                                        <?php echo $safeFavLang; ?>
                                    </p>
                                </div>
                                
                                <!-- Badge ID -->
                                <div class="bg-cyber-700 rounded-xl p-4">
                                    <p class="text-gray-500 text-xs uppercase tracking-wider mb-1">Badge ID</p>
                                    <p class="text-cyan-400 font-mono font-semibold tracking-wider">
                                        #<?php echo e($badgeId); ?>
                                    </p>
                                </div>
                                
                            </div>
                            
                            <!-- QR Code Placeholder (visual element) -->
                            <div class="flex items-center justify-between bg-cyber-700 rounded-xl p-4">
                                <div>
                                    <p class="text-gray-500 text-xs uppercase tracking-wider mb-1">Scan for Profile</p>
                                    <p class="text-gray-400 text-sm">Present at registration desk</p>
                                </div>
                                <div class="w-16 h-16 bg-white rounded-lg p-1">
                                    <!-- Simple QR-like pattern (decorative) -->
                                    <svg viewBox="0 0 100 100" class="w-full h-full">
                                        <rect x="0" y="0" width="30" height="30" fill="black"/>
                                        <rect x="70" y="0" width="30" height="30" fill="black"/>
                                        <rect x="0" y="70" width="30" height="30" fill="black"/>
                                        <rect x="10" y="10" width="10" height="10" fill="white"/>
                                        <rect x="80" y="10" width="10" height="10" fill="white"/>
                                        <rect x="10" y="80" width="10" height="10" fill="white"/>
                                        <rect x="40" y="0" width="20" height="10" fill="black"/>
                                        <rect x="40" y="40" width="20" height="20" fill="black"/>
                                        <rect x="0" y="40" width="10" height="20" fill="black"/>
                                        <rect x="90" y="40" width="10" height="20" fill="black"/>
                                        <rect x="40" y="90" width="20" height="10" fill="black"/>
                                        <rect x="70" y="70" width="30" height="30" fill="black"/>
                                        <rect x="80" y="80" width="10" height="10" fill="white"/>
                                    </svg>
                                </div>
                            </div>
                            
                        </div>
                        
                        <!-- Badge Footer -->
                        <div class="bg-cyber-700/50 px-8 py-4 border-t border-cyber-600">
                            <div class="flex items-center justify-between text-xs text-gray-500">
                                <span>Generated: <?php echo e(date('M j, Y • H:i')); ?></span>
                                <span class="flex items-center gap-1">
                                    <span class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                                    Verified
                                </span>
                            </div>
                        </div>
                        
                    </div>
                </div>
            </div>
            
            <!-- Action Buttons -->
            <div class="flex flex-col sm:flex-row gap-4 mt-8 no-print">
                <a 
                    href="index.php" 
                    class="flex-1 inline-flex items-center justify-center gap-2 px-6 py-3 bg-cyber-700 hover:bg-cyber-600 text-gray-300 hover:text-white font-semibold rounded-lg transition-colors border border-cyber-600"
                >
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path>
                    </svg>
                    Register Another
                </a>
                <button 
                    onclick="window.print()" 
                    class="flex-1 inline-flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-cyan-600 to-purple-600 hover:from-cyan-500 hover:to-purple-500 text-white font-semibold rounded-lg transition-all"
                >
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z"></path>
                    </svg>
                    Print Badge
                </button>
            </div>
            
            <?php endif; ?>
            
            <!-- Architecture Notes (visible in dev mode) -->
            <details class="mt-12 no-print">
                <summary class="cursor-pointer text-gray-600 hover:text-gray-400 text-sm">
                    🔒 Security Architecture Notes
                </summary>
                <div class="mt-4 bg-cyber-800 rounded-xl p-6 text-sm text-gray-400 space-y-4">
                    <div>
                        <h4 class="text-cyan-400 font-semibold mb-1">Guard Clause Pattern</h4>
                        <p>Request method is validated at the top of the file. Non-POST requests receive HTTP 403.</p>
                    </div>
                    <div>
                        <h4 class="text-cyan-400 font-semibold mb-1">XSS Prevention</h4>
                        <p>All user inputs wrapped in <code class="text-green-400">htmlspecialchars()</code> with ENT_QUOTES flag.</p>
                    </div>
                    <div>
                        <h4 class="text-cyan-400 font-semibold mb-1">Null Coalescing</h4>
                        <p>Missing POST keys handled gracefully with <code class="text-green-400">$_POST['key'] ?? ''</code></p>
                    </div>
                    <div>
                        <h4 class="text-cyan-400 font-semibold mb-1">Whitelist Validation</h4>
                        <p>Language selection validated against a hardcoded array of allowed values.</p>
                    </div>
                </div>
            </details>
            
        </div>
    </main>
    
</body>
</html>
