# SentinalScan v1.2
Web Application Vulnerability Scanner developed by Mike Stiuso

#### Disclaimer 
*- Simple scanner, to be used for experimental purposes only.*
<br> *- Will not find all vulnerabilities and might include false positivies*
<br> *- 100% Experimental*
### How does it work?
- **Checks for SQL Injection Vulnerabilities**
    by sending custom payloads into the websites forms.
- **Checks for Authentication Vulnerabilities**
    by checking the authentication token pattern, then checks if the url requires authentication, and if a vulnerabilitiy exists by sending an authorization header with token and checks status.
- **Checks for Cross Site Scripting Vulnerabilities** By searching for specific patterns in the response text, such as JavaScript event handlers or HTML tags that could be used to inject malicious code, the code can help identify potential XSS vulnerabilities
- **Checks for Cross Site Request Forgery Vulnerabilities** If CSRF token is found, the code adds the token to a dictionary named csrf_payload and sends a POST request to the specified url with the csrf_payload data.

![image](https://github.com/mikestussy/SentinalScan/assets/112903907/6c6e2562-8bf6-4e8f-8c2c-69a8795767b3)

