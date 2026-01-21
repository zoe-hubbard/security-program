This project creates a secure website for the user to login to various types of accounts.

uses flask application.

Fits the below security criteria: 


1. Apply Syntactic and Semantic Validation
    * Validate all input fields for:
        * Type - e.g., string, integer, boolean
        * Format - username must be a valid email address
        * Length  - minimum and maximum values appropriate to context
        * Logical correctness - e.g., dates are in the future, booleans are true/false. Include domain-specific rules where applicable (e.g., age must be greater than zero, dates must be in valid ranges).
2. Reject Invalid or Excessive Input
    * Prevent empty fields, overly long strings, or logically incorrect values.
    * Apply numeric ranges and length constraints where appropriate.
    * Validation must be enforced server-side.
3. Sanitise User-Generated Content Before Rendering or Storage
    * Neutralise potentially harmful content such as embedded scripts or event handlers before it is stored or displayed.
4. Use a Whitelist Approach for HTML Sanitisation
    * When allowing HTML input, only permit the following tags and attributes:
        * Tags: b, i, u, em, strong, a, p, ul, ol, li, br
        * Attributes: href, title (only on <a> tags)
        * All other tags and attributes must be removed or escaped.
5. Ensure Safe Rendering in Templates
    * Do not disable autoescaping in templates unless content is explicitly trusted and sanitised.
Your implementation should demonstrate awareness of input-related vulnerabilities such as SQL injection (CWE-89), cross-site scripting (CWE-79), and improper input validation (CWE-20).
 
Part B: Secure Authentication & Session Management
You must review the application’s authentication and session handling mechanisms and strengthen them to meet modern security standards. Your work should:
1. Improve Authentication Logic
    * Ensure that login, logout, and access to protected resources are handled securely.
    * Authentication must reliably verify user identity before granting access.
2. Enforce a Strong Password Policy
    * Passwords must:
        * Be at least 10 characters long.
        * Include at least one uppercase letter, one digit, and one special character.
        * Not contain any part of the username (i.e., email address).
        * Not match entries in a custom blacklist. The blacklist must include at least: Password123$, Qwerty123!, Adminadmin1@, weLcome123!.
        * Avoid repeated character sequences (e.g., aaa, 111, !!!).
3. Strengthen Session Management
    * Implement measures that prevent session fixation and reduce exposure to interception or misuse.
    * Sessions should be renewed after authentication and configured to minimize client-side risks.
4. Protect Sensitive Operations
    * Require reauthentication for critical actions such as password changes, and ensure all session and cookie settings support confidentiality and integrity.
Your implementation should demonstrate awareness of authentication-related vulnerabilities such as CWE-287 (Improper Authentication), CWE-798 (Hardcoded Credentials), and CWE-614 (Sensitive Cookie in HTTPS Session Without Secure Flag).
 
Part C: SQL Injection Mitigation
You must review the application for vulnerabilities related to SQL injection and implement appropriate safeguards. Your work should:
1. Identify Risk Areas
    * Examine all parts of the application where database queries are constructed and determine where user input could influence query logic.
2. Apply Secure Query Practices
    * Ensure that query construction prevents injection attacks by separating query logic from user-supplied data.
    * Use techniques that enforce safe handling of parameters and avoid insecure patterns.
3. Demonstrate Awareness of CWE-89
    * Ensure your approach mitigates risks associated with improper neutralization of special elements in SQL commands.
Your implementation should reflect secure coding principles and align with industry standards for preventing SQL injection.
 
Part D: Cross-Site Scripting (XSS) & CSRF Protection
You must identify and mitigate vulnerabilities related to client-side script injection and unauthorized state-changing requests. Your implementation should:
1. Address XSS Risks
    * Ensure that user-generated content does not lead to script execution in the browser.
    * Consider how data is rendered in templates and how dynamic content is handled in different contexts (HTML, JavaScript, attributes).
    * Avoid practices that could allow malicious scripts to run.
2. Implement CSRF Defenses
    * All operations that modify server-side state must include mechanisms to confirm the legitimacy of the request.
    * Ensure that these protections are consistently applied across all relevant routes and forms.
3. Maintain Secure Rendering Practices
    * Review template logic and output handling to prevent unsafe injection points.
    * Pay attention to areas where user input might appear in scripts, event handlers, or attributes.
Your implementation should demonstrate awareness of CWE-79 (Improper Neutralisation of Input During Web Page Generation) and CWE-352 (Cross-Site Request Forgery).
 
Part E: HTTP Security Headers
You must evaluate and improve the HTTP response headers used by the application to strengthen browser-side security. Your work should:
1. Assess Current Header Configuration
    * Review the headers currently returned by the application and identify any missing or misconfigured security-related headers.
2. Apply Security Headers Consistently
    * Ensure that all responses include headers that help mitigate common browser-based threats.
    * These should support secure transport, restrict content sources, and limit unnecessary browser features.
    * Local JavaScript (Greet Me button) and CSS (General webpage styling) assets must still function.
3. Avoid Unsafe Defaults
    * Do not allow overly permissive settings that could enable attacks such as clickjacking or content injection.
    * Ensure that headers do not expose internal application details.
Your implementation should demonstrate awareness of browser-side protections and reflect mitigation of risks such as clickjacking, MIME-type sniffing, insecure content loading, and excessive feature exposure.
 
Part F: Authorisation & Route Protection
You must review and strengthen the application’s access control mechanisms to prevent unauthorized access and privilege escalation. Your work should:
1. Enforce Role-Based Access Control
    * Ensure that access to routes and features is restricted according to user roles.
    * Only authorized users should be able to reach sensitive areas.
2. Prevent Privilege Escalation
    * Implement measures that stop users from gaining higher-level privileges or accessing resources belonging to other users.
3. Protect Sensitive Routes
    * Ensure that unauthenticated users cannot access protected areas and that role checks are enforced consistently on the server side.
Your implementation should demonstrate awareness of vulnerabilities such as CWE-284 (Improper Access Control), CWE-285 (Improper Authorization), and CWE-639 (Authorization Bypass Through User-Controlled) 
 
Part G: Cryptography
You must review how sensitive data is stored and transmitted within the application and apply appropriate cryptographic protections. Your work should:
1. Secure Password Storage
    * Ensure passwords are stored using a strong, one-way hashing approach.
    * Include measures that make hashes resistant to brute-force and rainbow table attacks, including the use of salting and peppering.
2. Protect User-Generated Content
    * Evaluate how user biographies are stored and displayed.
    * Implement encryption for biographies before storing them in the database.
    * Consider how to securely decrypt and render this content while maintaining confidentiality and usability.
3. Restrict Access to Secrets
    * Ensure secrets (e.g., keys, tokens) are only accessible to components that require them.
    * Apply least privilege principles to configuration and runtime environments.
Your implementation should demonstrate awareness of cryptographic risks such as CWE-321 (Use of Hard-coded Cryptographic Key), CWE-327 (Use of Broken or Risky Cryptographic Algorithm), and CWE-798 (Use of Hard-coded Credentials).
 
Part H: Secure Logging & Monitoring
You must implement logging and monitoring features that support security awareness and incident detection. Your implementation must:
1. Log Key Security Events
    * Record events such as failed login attempts, validation failures, access control violations, and password changes.
    * Include relevant contextual information such as timestamp, IP address, and user ID.
    * Log both successful and failed actions where you think appropriate.
2. Use Structured Logging
    * Format logs consistently to support readability and automated analysis.
    * Include severity levels to distinguish between informational, warning, and error events.
3. Log Database Query Events Securely
    * Do not log sensitive data such as passwords, tokens, or session identifiers.
4. Log Retention & Rotation
    * Implement file‑based logging with rotation to prevent unbounded growth.
    * Use a rotating handler that limits file size to 1MB per log file and keeps a small, fixed number of 5 backups.
Your implementation should demonstrate awareness of secure logging practices and reflect mitigation of risks such as CWE-532 (Information Exposure Through Log Files) and CWE-778 (Insufficient Logging).
 
Part I: Error Handling & Flask Configuration
You must audit and improve the application's error handling and configuration to reduce information exposure and support secure deployment. Your implementation must:
1. Avoid Exposing Sensitive Error Information
    * Ensure that stack traces, internal messages, and debug output are not shown to users.
    * Replace default error responses with custom error pages for:
        * Bad Request
        * Forbidden
        * Not Found
        * Internal Server Error
    * Custom error pages must have same styling as all other pages.
2. Secure Flask Configuration
    * Use configuration classes to separate development and production settings.
    * Disable debug mode in production environments.
    * Ensure that sensitive configuration values (i.e., keys and database URI) are not hardcoded in production environments.
3. Support Environment-Specific Behaviour
    * Ensure the application behaves appropriately depending on the environment (e.g., development vs production).
Your implementation should demonstrate awareness of CWE-209 (Information Exposure Through an Error Message) and CWE-489 (Active Debug Code).
