# Tracing the Hook

## Objective

The objective of this project was to investigate and respond to a phishing email campaign scenario presented in the TryHackMe room titled "An Ordinary Midsummer Day...". The project involved a deep dive into phishing email analysis, identification of malicious URLs, and phishing kit investigation. The goal was to simulate real-world SOC procedures in tracking adversarial infrastructure and compromised credentials stemming from a targeted phishing attack.

## Skills Learned

- Phishing Email Analysis: Examined email headers and contents to identify malicious sender details and delivery patterns.
- URL & Redirection Tracking: Investigated phishing URLs, including decoding defanged links and tracking redirections specific to targeted users.
- Phishing Kit Forensics: Retrieved and analyzed a phishing kit ZIP archive, verifying integrity via SHA256 hashes.
- Cyber Threat Intelligence (CTI): Used tools like VirusTotal, SSL cert transparency logs, and WHOIS to attribute infrastructure and timeline of the attack.
- Victim Identification & Behavior Analysis: Identified affected employees (e.g., William McClean, Michael Ascot) and their actions, such as repeated credential submission.
- IOC Extraction & Correlation: Collected key Indicators of Compromise including attacker email addresses.
  
## Tools Used

- TryHackMe paltform for accessing the Lab
- VirusTotal – To scan URLs, files, and retrieve intelligence on the phishing kit hash.
- Cyberchef: To decode obfuscated URLs and encoded payloads.
- Ubuntu Terminal: Command-line interface for executing the Tool.
- Virtual Machine (VM): Simulated environment for executing tasks.
- Firefox Developer Edition – For safely browsing phishing URLs in a controlled environment.

## Scenario


An Ordinary Midsummer Day...

As an IT department personnel of SwiftSpend Financial, one of your responsibilities is to support your fellow employees with their technical concerns. While everything seemed ordinary and mundane, this gradually changed when several employees from various departments started reporting an unusual email they had received. Unfortunately, some had already submitted their credentials and could no longer log in.

You now proceeded to investigate what is going on by:
- Analysing the email samples provided by your colleagues.
- Analysing the phishing URL(s) by browsing it using Firefox.
- Retrieving the phishing kit used by the adversary.
- Using CTI-related tooling to gather more information about the adversary.
- Analysing the phishing kit to gather more information about the adversary.

## Steps taken

Q1. Who is the individual who received an email attachment containing a PDF?<br>
Ans : William McClean<br>
O/P: <img src="https://github.com/user-attachments/assets/1e9edf07-fbce-47d0-85e7-e3bcc531ea72" />
    <img src="https://github.com/user-attachments/assets/dc6f08b0-d57e-4baa-8c35-5e31cb69e752" /> <br><br>

Q2. What email address was used by the adversary to send the phishing emails?<br>
Ans : Accounts.Payable@groupmarketingonline.icu<br>
O/P: <img src="https://github.com/user-attachments/assets/1ac06cd0-7c4e-4455-bd33-842af98431ec" /> <br><br>

Q3. What is the redirection URL to the phishing page for the individual Zoe Duncan? (defanged format)<br>
Ans : hxxp[://]kennaroads[.]buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe[.]duncan@swiftspend[.]finance&error<br>
O/P: <img src="https://github.com/user-attachments/assets/8aac87d5-04a4-4b3e-baf7-e7d386741a04" /> 
 <img src="https://github.com/user-attachments/assets/9dafa5e7-f8c8-49e5-8ba2-b05b53f62a28" /> 
  <img src="https://github.com/user-attachments/assets/21c8a028-8607-487c-bd67-e8249f1fbae9" /> <br><br>

Q4. What is the URL to the .zip archive of the phishing kit? (defanged format)<br>
Ans : hxxp[://]kennaroads[.]buzz/data/Update365[.]zip<br>
O/P: <img src="https://github.com/user-attachments/assets/f4b3e58c-ba23-4a84-8e0b-3bb3857062bf" />
<img src="https://github.com/user-attachments/assets/851fae61-25f0-4540-a8e8-5605f973a1f7" /> <br><br>

Q5. What is the SHA256 hash of the phishing kit archive?<br>
Ans : ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686<br>
O/P: <img src="https://github.com/user-attachments/assets/4071b113-6c03-45ed-a61c-84ce5360d461" /> <br><br>

Q6. When was the phishing kit archive first submitted? (format: YYYY-MM-DD HH:MM:SS UTC) <br>
Ans : 2020-04-08 21:55:50 UTC<br>
O/P: <img src="https://github.com/user-attachments/assets/38d9d26e-2c31-4194-a717-2879143908b5" /> <br><br>

Q7. What was the email address of the user who submitted their password twice?<br>
Ans : michael.ascot@swiftspend.finance<br>
O/P: <img src="https://github.com/user-attachments/assets/d59046cd-c050-4e3c-bb2f-913f0fd4ff43" /> <br><br>

Q8. What was the email address used by the adversary to collect compromised credentials?<br>
Ans : m3npat@yandex.com<br>
O/P: <img src="https://github.com/user-attachments/assets/abe697fb-de50-4953-966e-0aac4dea50df" /> <br><br>

Q9. The adversary used other email addresses in the obtained phishing kit. What is the email address that ends in "@gmail.com"?<br>
Ans : jamestanner2299@gmail.com<br>
O/P: <img src="https://github.com/user-attachments/assets/c9947021-3e05-4918-96b6-6292a5040733" /> <br><br>

Q10. What is the hidden flag?<br>
Ans : THM{pL4y_w1Th_tH3_URL}<br>
O/P: <img src="https://github.com/user-attachments/assets/edc0f5f3-e752-448d-a883-0a1ed767af34" />
<img src="https://github.com/user-attachments/assets/81669b87-f292-4035-bf77-3646a1270733" /><br><br>


## Conclusion

This project simulated a realistic phishing incident response case through the TryHackMe platform, showcasing the tactics used by attackers and the corresponding defensive actions taken by security teams. By analyzing phishing emails, tracing URLs, and extracting data from phishing kits, I was able to understand the full lifecycle of a phishing campaign. This hands-on experience emphasized how crucial email security and CTI are in real-world scenarios, and how methodical investigation using forensic tools can help mitigate breaches. Overall, PhishTrail deepened my skills in phishing analysis and email-based threat detection within a structured, practical environment.
