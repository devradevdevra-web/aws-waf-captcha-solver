# AWS WAF CAPTCHA Solver

An automated, efficient tool designed to bypass and solve AWS WAF (Web Application Firewall) CAPTCHAs.

This solver automates the process of interacting with the CAPTCHA challenge, processing the necessary inputs, and returning a valid authorization token so you can continue your scraping or automated tasks without interruption.

🚀 How It Works

The solver follows a straightforward pipeline to bypass the WAF protection:

Grabs the Challenge (Goku)  -> Processes Inputs -> Solves -> Returns AWS Token

Grabs "Goku": Intercepts and extracts the initial AWS WAF CAPTCHA challenge payload/parameters.

Inputs: Feeds the payload into the solver logic.

Solves: Executes the background bypass sequence.

Output: Returns a valid aws-waf-token cookie which you can inject into your headers to access the protected site.

Milestone: Image Recognition Version

Currently, this repository handles standard solver bypasses. However, I have an advanced Image Recognition Version in the works!

⭐ 20 STAR GOAL: Once this repository reaches 20 Stars, I will officially release and upload the Image Recognition version of this solver! Star the repo to show your support and get the update!


⚠️ Disclaimer

This tool is created for educational purposes and authorized penetration testing only. Please respect the terms of service of the websites you interact with. The author is not responsible for any misuse of this software.
