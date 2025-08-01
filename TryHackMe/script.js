const roomsData = [
    // --- Intro ---
    { name: 'Hosted Hypervisors', category: 'Intro', difficulty: 'Intro', description: 'Learn about hosted hypervisors.', tags: ['intro', 'virtualization'] },
    { name: 'Enumeration & Brute Force', category: 'Intro', difficulty: 'Intro', description: 'Learn about enumeration and brute force attacks.', tags: ['intro', 'pentesting'] },
    { name: 'Introduction to Cryptops', category: 'Intro', difficulty: 'Intro', description: 'An introduction to cryptography operations.', tags: ['intro', 'crypto'] },
    { name: 'Linux File System Analysis', category: 'Intro', difficulty: 'Intro', description: 'Learn how to analyze the Linux file system.', tags: ['intro', 'linux', 'forensics'] },
    { name: 'Threat Hunting: Foothold', category: 'Intro', difficulty: 'Intro', description: 'Learn how to hunt for footholds in a network.', tags: ['intro', 'blue team', 'threat hunting'] },
    { name: 'Threat Hunting: Introduction', category: 'Intro', difficulty: 'Intro', description: 'An introduction to threat hunting.', tags: ['intro', 'blue team', 'threat hunting'] },
    { name: 'Preparation', category: 'Intro', difficulty: 'Intro', description: 'Learn how to prepare for a penetration test.', tags: ['intro', 'pentesting'] },
    { name: 'Intro to Logs', category: 'Intro', difficulty: 'Intro', description: 'An introduction to log analysis.', tags: ['intro', 'blue team', 'forensics'] },
    { name: 'Intro to Threat Emulation', category: 'Intro', difficulty: 'Intro', description: 'An introduction to threat emulation.', tags: ['intro', 'red team'] },
    { name: 'Security Engineer Intro', category: 'Intro', difficulty: 'Intro', description: 'An introduction to the role of a security engineer.', tags: ['intro', 'career'] },
    { name: 'Intro to Docker', category: 'Intro', difficulty: 'Intro', description: 'An introduction to Docker.', tags: ['intro', 'docker', 'devops'] },
    { name: 'SDLC', category: 'Intro', difficulty: 'Intro', description: 'An introduction to the Software Development Life Cycle.', tags: ['intro', 'devops'] },
    { name: 'Welcome', category: 'Intro', difficulty: 'Intro', description: 'A welcome room to introduce you to the TryHackMe platform.', tags: ['intro', 'platform'] },
    { name: 'How to use TryHackMe', category: 'Intro', difficulty: 'Intro', description: 'A detailed guide on navigating and using the TryHackMe site.', tags: ['intro', 'platform'] },
    { name: 'Tutorial', category: 'Intro', difficulty: 'Intro', description: 'Learn the basics of using TryHackMe and its features.', tags: ['intro', 'tutorial'] },
    { name: 'OpenVPN', category: 'Intro', difficulty: 'Intro', description: 'Learn how to connect to the TryHackMe network using OpenVPN.', tags: ['vpn', 'networking'] },
    { name: 'Learning Cyber Security', category: 'Intro', difficulty: 'Intro', description: 'A general introduction to learning cyber security.', tags: ['intro', 'career'] },
    { name: 'Starting Out In Cyber Sec', category: 'Intro', difficulty: 'Intro', description: 'Learn about the different careers in cyber security.', tags: ['career', 'intro'] },
    { name: 'Introductory Researching', category: 'Intro', difficulty: 'Intro', description: 'Learn how to use search engines to find information.', tags: ['osint', 'research'] },
    { name: 'Regular expressions', category: 'Intro', difficulty: 'Intro', description: 'Learn how to use regular expressions.', tags: ['intro', 'scripting'] },
    { name: 'Careers in Cyber', category: 'Intro', difficulty: 'Intro', description: 'Learn about the different careers in cyber security.', tags: ['intro', 'career'] },
    { name: 'Junior Security Analyst Intro', category: 'Intro', difficulty: 'Intro', description: 'An introduction to the role of a junior security analyst.', tags: ['intro', 'career', 'blue team'] },

    // --- Easy ---
    { name: 'Linux Modules', category: 'Linux', difficulty: 'Easy', description: 'Learn about Linux kernel modules.', tags: ['linux', 'kernel'] },
    { name: 'Linux Fundamentals Part 1', category: 'Linux', difficulty: 'Easy', description: 'Get started with the basic Linux commands and concepts.', tags: ['linux', 'bash', 'commands'] },
    { name: 'Linux Fundamentals Part 2', category: 'Linux', difficulty: 'Easy', description: 'Continue your journey with more advanced Linux commands.', tags: ['linux', 'bash', 'permissions'] },
    { name: 'Linux Fundamentals Part 3', category: 'Linux', difficulty: 'Easy', description: 'Master text manipulation and process management in Linux.', tags: ['linux', 'bash', 'automation'] },
    { name: 'Windows Fundamentals 1', category: 'Windows', difficulty: 'Easy', description: 'Get started with the Windows operating system.', tags: ['windows', 'system32'] },
    { name: 'Windows Fundamentals 2', category: 'Windows', difficulty: 'Easy', description: 'Learn about Windows networking and user management.', tags: ['windows', 'networking', 'users'] },
    { name: 'Windows Fundamentals 3', category: 'Windows', difficulty: 'Easy', description: 'Explore Windows security features and logging.', tags: ['windows', 'security', 'event log'] },
    { name: 'Basic Pentesting', category: 'Web', difficulty: 'Easy', description: 'A room to practice basic penetration testing skills.', tags: ['web', 'pentesting'] },
    { name: 'Pentesting Fundamentals', category: 'Basics', difficulty: 'Easy', description: 'Learn the fundamentals of penetration testing.', tags: ['pentesting', 'basics'] },
    { name: 'Principles of Security', category: 'Basics', difficulty: 'Easy', description: 'Learn the basic principles of security.', tags: ['security', 'basics'] },
    { name: 'The Hacker Methodology', category: 'Recon', difficulty: 'Easy', description: 'Learn about the hacker methodology.', tags: ['pentesting', 'recon'] },
    { name: 'Physical Security Intro', category: 'Recon', difficulty: 'Easy', description: 'An introduction to physical security.', tags: ['physical security', 'recon'] },
    { name: 'Linux Strength Training', category: 'Linux', difficulty: 'Easy', description: 'Train your Linux command line skills.', tags: ['linux', 'bash'] },
    { name: 'OpenVAS', category: 'Recon', difficulty: 'Easy', description: 'Learn how to use the OpenVAS vulnerability scanner.', tags: ['openvas', 'recon', 'tooling'] },
    { name: 'ISO27001', category: 'Recon', difficulty: 'Easy', description: 'An introduction to the ISO27001 standard.', tags: ['iso27001', 'compliance'] },
    { name: 'Passive Reconnaissance', category: 'Recon', difficulty: 'Easy', description: 'Learn how to perform passive reconnaissance.', tags: ['osint', 'recon'] },
    { name: 'Active Reconnaissance', category: 'Recon', difficulty: 'Easy', description: 'Learn how to perform active reconnaissance.', tags: ['recon', 'scanning'] },
    { name: 'Content Discovery', category: 'Recon', difficulty: 'Easy', description: 'Learn how to discover hidden content on web servers.', tags: ['web', 'recon'] },
    { name: 'OhSINT', category: 'Recon', difficulty: 'Easy', description: 'A room to practice your OSINT skills.', tags: ['osint', 'recon'] },
    { name: 'Shodan.io', category: 'Recon', difficulty: 'Easy', description: 'Learn how to use the Shodan search engine.', tags: ['shodan', 'recon', 'iot'] },
    { name: 'Google Dorking', category: 'Recon', difficulty: 'Easy', description: 'Learn how to use Google dorks to find information.', tags: ['osint', 'google dorking'] },
    { name: 'WebOSINT', category: 'Recon', difficulty: 'Easy', description: 'A room to practice your web OSINT skills.', tags: ['osint', 'web'] },
    { name: 'Sakura Room', category: 'Recon', difficulty: 'Easy', description: 'A room to practice your OSINT skills.', tags: ['osint', 'recon'] },
    { name: 'Python Basics', category: 'Scripting', difficulty: 'Easy', description: 'Learn the basics of Python.', tags: ['python', 'scripting'] },
    { name: 'Python Playground', category: 'Scripting', difficulty: 'Easy', description: 'A playground to practice your Python skills.', tags: ['python', 'scripting'] },
    { name: 'JavaScript Basics', category: 'Scripting', difficulty: 'Easy', description: 'Learn the basics of JavaScript.', tags: ['javascript', 'scripting'] },
    { name: 'Bash Scripting', category: 'Scripting', difficulty: 'Easy', description: 'Learn how to write bash scripts.', tags: ['bash', 'scripting', 'linux'] },
    { name: 'Introductory Networking', category: 'Networking', difficulty: 'Easy', description: 'Learn the fundamentals of networking, including the OSI and TCP/IP models.', tags: ['networking', 'osi', 'tcp/ip'] },
    { name: 'What is Networking?', category: 'Networking', difficulty: 'Easy', description: 'An introduction to networking.', tags: ['networking', 'basics'] },
    { name: 'Intro to LAN', category: 'Networking', difficulty: 'Easy', description: 'An introduction to Local Area Networks.', tags: ['networking', 'lan'] },
    { name: 'HTTP in detail', category: 'Networking', difficulty: 'Easy', description: 'A detailed look at the HTTP protocol.', tags: ['networking', 'http', 'web'] },
    { name: 'DNS in detail', category: 'Networking', difficulty: 'Easy', description: 'A detailed look at the DNS protocol.', tags: ['networking', 'dns'] },
    { name: 'Snyk Open Source', category: 'Tooling', difficulty: 'Easy', description: 'Learn how to use Snyk to find vulnerabilities in open source code.', tags: ['snyk', 'tooling', 'devsecops'] },
    { name: 'Snyk Code', category: 'Tooling', difficulty: 'Easy', description: 'Learn how to use Snyk to find vulnerabilities in your own code.', tags: ['snyk', 'tooling', 'devsecops'] },
    { name: 'Intro to laC', category: 'Tooling', difficulty: 'Easy', description: 'An introduction to Infrastructure as Code.', tags: ['iac', 'devops'] },
    { name: 'Metasploit: Introduction', category: 'Tooling', difficulty: 'Easy', description: 'Get hands-on with the Metasploit Framework for exploitation.', tags: ['metasploit', 'exploit', 'tooling'] },
    { name: 'tmux', category: 'Tooling', difficulty: 'Easy', description: 'Learn how to use the tmux terminal multiplexer.', tags: ['tmux', 'tooling', 'linux'] },
    { name: 'REmux The Tmux', category: 'Tooling', difficulty: 'Easy', description: 'A room to practice your tmux skills.', tags: ['tmux', 'tooling', 'linux'] },
    { name: 'Hydra', category: 'Tooling', difficulty: 'Easy', description: 'Learn how to use Hydra to brute-force logins.', tags: ['hydra', 'brute force', 'passwords'] },
    { name: 'Toolbox: Vim', category: 'Tooling', difficulty: 'Easy', description: 'Learn how to use the Vim text editor.', tags: ['vim', 'tooling', 'linux'] },
    { name: 'Introduction to OWASP ZAP', category: 'Tooling', difficulty: 'Easy', description: 'Learn how to use the OWASP ZAP vulnerability scanner.', tags: ['owasp zap', 'tooling', 'web'] },
    { name: 'Phishing: Hidden Eye', category: 'Tooling', difficulty: 'Easy', description: 'Learn how to use the Hidden Eye phishing tool.', tags: ['phishing', 'tooling'] },
    { name: 'RustScan', category: 'Tooling', difficulty: 'Easy', description: 'Learn how to use the RustScan port scanner.', tags: ['rustscan', 'tooling', 'networking'] },
    { name: 'Nessus', category: 'Tooling', difficulty: 'Easy', description: 'Learn how to use the Nessus vulnerability scanner.', tags: ['nessus', 'tooling', 'recon'] },
    { name: 'Nmap Live Host Discovery', category: 'Tooling', difficulty: 'Easy', description: 'Learn how to use Nmap to discover live hosts.', tags: ['nmap', 'tooling', 'networking'] },
    { name: 'Nmap', category: 'Networking', difficulty: 'Easy', description: 'Master the Nmap scanner, an essential tool for any hacker.', tags: ['nmap', 'scanning', 'recon', 'tooling'] },
    { name: 'ffuf', category: 'Tooling', difficulty: 'Easy', description: 'Learn how to use the ffuf web fuzzer.', tags: ['ffuf', 'tooling', 'web'] },
    { name: 'Burp Suite: The Basics', category: 'Tooling', difficulty: 'Easy', description: 'Learn the essentials of Burp Suite for web application testing.', tags: ['burp suite', 'web', 'proxy'] },
    { name: 'Burp Suite: Repeater', category: 'Tooling', difficulty: 'Easy', description: 'Learn how to use the Repeater tool in Burp Suite.', tags: ['burp suite', 'tooling', 'web'] },
    { name: 'Cryptography for Dummies', category: 'Cryptography', difficulty: 'Easy', description: 'An introduction to cryptography.', tags: ['crypto', 'basics'] },
    { name: 'Crack the hash', category: 'Cryptography', difficulty: 'Easy', description: 'A room to practice your hash cracking skills.', tags: ['crypto', 'hash cracking'] },
    { name: 'Agent Sudo', category: 'Cryptography', difficulty: 'Easy', description: 'A CTF with a focus on cryptography.', tags: ['ctf', 'crypto'] },
    { name: 'Brute It', category: 'Cryptography', difficulty: 'Easy', description: 'A room to practice your brute-forcing skills.', tags: ['crypto', 'brute force'] },
    { name: 'Introduction to Cryptography', category: 'Cryptography', difficulty: 'Easy', description: 'An introduction to cryptography.', tags: ['crypto', 'basics'] },
    { name: 'CC: Steganography', category: 'Steganography', difficulty: 'Easy', description: 'A room to practice your steganography skills.', tags: ['steganography', 'forensics'] },
    { name: 'Musical Stego', category: 'Steganography', difficulty: 'Easy', description: 'A room to practice your audio steganography skills.', tags: ['steganography', 'audio'] },
    { name: 'Madness', category: 'Steganography', difficulty: 'Easy', description: 'A room to practice your steganography skills.', tags: ['steganography', 'forensics'] },
    { name: 'Psycho Break', category: 'Steganography', difficulty: 'Easy', description: 'A room to practice your steganography skills.', tags: ['steganography', 'forensics'] },
    { name: 'XSS', category: 'Web', difficulty: 'Easy', description: 'Learn how to find and exploit Cross-Site Scripting vulnerabilities.', tags: ['web', 'xss', 'javascript'] },
    { name: 'CSRF', category: 'Web', difficulty: 'Easy', description: 'Learn how to exploit Cross-Site Request Forgery vulnerabilities.', tags: ['web', 'csrf'] },
    { name: 'File Inclusion, Path Traversal', category: 'Web', difficulty: 'Easy', description: 'Learn how to exploit file inclusion and path traversal vulnerabilities.', tags: ['web', 'lfi', 'rfi'] },
    { name: 'SSRF', category: 'Web', difficulty: 'Easy', description: 'Learn how to exploit Server-Side Request Forgery vulnerabilities.', tags: ['web', 'ssrf'] },
    { name: 'OWASP Broken Access Control', category: 'Web', difficulty: 'Easy', description: 'Learn about broken access control vulnerabilities.', tags: ['web', 'owasp'] },
    { name: 'Vulnerabilities 101', category: 'Web', difficulty: 'Easy', description: 'An introduction to web vulnerabilities.', tags: ['web', 'basics'] },
    { name: 'Walking An Application', category: 'Web', difficulty: 'Easy', description: 'Learn how to manually walk through a web application.', tags: ['web', 'recon'] },
    { name: 'OWASP Top 10-2021', category: 'Web', difficulty: 'Easy', description: 'An overview of the OWASP Top 10 2021.', tags: ['web', 'owasp'] },
    { name: 'OWASP Top 10', category: 'Web', difficulty: 'Easy', description: 'An overview of the OWASP Top 10.', tags: ['web', 'owasp'] },
    { name: 'OWASP Juice Shop', category: 'Web', difficulty: 'Easy', description: 'Hack a modern, insecure web application with dozens of challenges.', tags: ['web', 'owasp top 10', 'ctf'] },
    { name: 'OWASP Mutillidae II', category: 'Web', difficulty: 'Easy', description: 'A vulnerable web application to practice your skills on.', tags: ['web', 'owasp', 'pentesting'] },
    { name: 'WebGOAT', category: 'Web', difficulty: 'Easy', description: 'A vulnerable web application to practice your skills on.', tags: ['web', 'owasp', 'pentesting'] },
    { name: 'Web Application Security', category: 'Web', difficulty: 'Easy', description: 'An introduction to web application security.', tags: ['web', 'basics'] },
    { name: 'DVWA', category: 'Web', difficulty: 'Easy', description: 'A vulnerable web application to practice your skills on.', tags: ['web', 'owasp', 'pentesting'] },
    { name: 'VulnNet', category: 'Web', difficulty: 'Easy', description: 'A vulnerable network to practice your skills on.', tags: ['networking', 'pentesting'] },
    { name: 'Juicy Details', category: 'Web', difficulty: 'Easy', description: 'A room to practice your web enumeration skills.', tags: ['web', 'recon'] },
    { name: 'Vulnversity', category: 'Web', difficulty: 'Easy', description: 'A great starting point to learn about common web vulnerabilities.', tags: ['web', 'pentesting', 'owasp'] },
    { name: 'SQL Injection Lab', category: 'Web', difficulty: 'Easy', description: 'A lab to practice your SQL injection skills.', tags: ['web', 'sqli'] },
    { name: 'SQL Injection', category: 'Web', difficulty: 'Easy', description: 'Learn to identify and exploit SQL injection vulnerabilities.', tags: ['web', 'sqli', 'database'] },
    { name: 'Ignite', category: 'Web', difficulty: 'Easy', description: 'A default CMS installation is a gift for a hacker. Exploit it.', tags: ['ctf', 'web', 'cms'] },
    { name: 'Overpass', category: 'Web', difficulty: 'Easy', description: 'A room to practice your web enumeration skills.', tags: ['web', 'recon'] },
    { name: 'Year of the Rabbit', category: 'Web', difficulty: 'Easy', description: 'A CTF for the Year of the Rabbit.', tags: ['ctf', 'fun', 'zodiac'] },
    { name: 'Jack-of-All-Trades', category: 'Web', difficulty: 'Easy', description: 'A CTF with a variety of challenges.', tags: ['ctf', 'collection'] },
    { name: 'Bolt', category: 'Web', difficulty: 'Easy', description: 'A CTF with a focus on a specific CMS.', tags: ['ctf', 'web', 'cms'] },
    { name: 'Android Hacking 101', category: 'Android', difficulty: 'Easy', description: 'An introduction to Android hacking.', tags: ['android', 'mobile'] },
    { name: 'Intro to Cold System Forensics', category: 'Forensics', difficulty: 'Easy', description: 'An introduction to cold system forensics.', tags: ['forensics', 'basics'] },
    { name: 'Unified Kill Chain', category: 'Forensics', difficulty: 'Easy', description: 'Learn about the Unified Kill Chain.', tags: ['forensics', 'blue team'] },
    { name: 'Forensic Imaging', category: 'Forensics', difficulty: 'Easy', description: 'Learn how to create forensic images.', tags: ['forensics', 'basics'] },
    { name: 'IR Philosophy and Ethics', category: 'Forensics', difficulty: 'Easy', description: 'Learn about the philosophy and ethics of incident response.', tags: ['forensics', 'blue team'] },
    { name: 'Legal Considerations in DFIR', category: 'Forensics', difficulty: 'Easy', description: 'Learn about the legal considerations in digital forensics and incident response.', tags: ['forensics', 'legal'] },
    { name: 'Cyber Kill Chain', category: 'Forensics', difficulty: 'Easy', description: 'Learn about the Cyber Kill Chain.', tags: ['forensics', 'blue team'] },
    { name: 'Identification & Scoping', category: 'Forensics', difficulty: 'Easy', description: 'Learn how to identify and scope an incident.', tags: ['forensics', 'blue team'] },
    { name: 'Wifi Hacking 101', category: 'Wi-Fi Hacking', difficulty: 'Easy', description: 'An introduction to Wi-Fi hacking.', tags: ['wifi', 'networking'] },
    { name: 'Forensics', category: 'Forensics', difficulty: 'Easy', description: 'A room to practice your forensics skills.', tags: ['forensics', 'ctf'] },
    { name: 'Intro to x86-64', category: 'Reverse Engineering', difficulty: 'Easy', description: 'An introduction to the x86-64 architecture.', tags: ['reversing', 'assembly'] },
    { name: 'Reversing ELF', category: 'Reverse Engineering', difficulty: 'Easy', description: 'Learn how to reverse engineer ELF files.', tags: ['reversing', 'linux'] },
    { name: 'Intro to Detection Engineering', category: 'Malware Analysis', difficulty: 'Easy', description: 'An introduction to detection engineering.', tags: ['malware', 'blue team'] },
    { name: 'History of Malware', category: 'Malware Analysis', difficulty: 'Easy', description: 'Learn about the history of malware.', tags: ['malware', 'history'] },
    { name: 'MAL: Malware Introductory', category: 'Malware Analysis', difficulty: 'Easy', description: 'An introduction to malware.', tags: ['malware', 'basics'] },
    { name: 'Basic Malware RE', category: 'Malware Analysis', difficulty: 'Easy', description: 'Learn the basics of malware reverse engineering.', tags: ['malware', 'reversing'] },
    { name: 'MAL: Researching', category: 'Malware Analysis', difficulty: 'Easy', description: 'Learn how to research malware.', tags: ['malware', 'osint'] },
    { name: 'Linux Privilege Escalation', category: 'PrivEsc', difficulty: 'Easy', description: 'Learn the basics of Linux privilege escalation.', tags: ['linux', 'privesc'] },
    { name: 'Windows PrivEsc', category: 'PrivEsc', difficulty: 'Easy', description: 'Learn the basics of Windows privilege escalation.', tags: ['windows', 'privesc'] },
    { name: 'Sudo Security Bypass', category: 'PrivEsc', difficulty: 'Easy', description: 'Learn how to bypass sudo security.', tags: ['linux', 'privesc', 'sudo'] },
    { name: 'Blaster', category: 'PrivEsc', difficulty: 'Easy', description: 'A room to practice your privilege escalation skills.', tags: ['privesc', 'ctf'] },
    { name: 'c4ptur3-th3-fl4g', category: 'PrivEsc', difficulty: 'Easy', description: 'A CTF with a focus on privilege escalation.', tags: ['ctf', 'privesc'] },
    { name: 'Blueprint', category: 'Windows', difficulty: 'Easy', description: 'A room to practice your Windows enumeration skills.', tags: ['windows', 'recon'] },
    { name: 'VulnNet: Active', category: 'CTF', difficulty: 'Easy', description: 'An Active Directory focused VulnNet room.', tags: ['ctf', 'active directory'] },
    { name: 'Anthem', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on web vulnerabilities.', tags: ['ctf', 'web'] },
    { name: 'Active Directory Basics', category: 'Active Directory', difficulty: 'Easy', description: 'Learn the basics of Active Directory.', tags: ['active directory', 'windows'] },
    { name: 'Overpass 2 - Hacked', category: 'PCAP Analysis', difficulty: 'Easy', description: 'Analyze network traffic to find out what happened.', tags: ['pcap', 'forensics', 'networking'] },
    { name: 'Intro To Pwntools', category: 'Buffer Overflow', difficulty: 'Easy', description: 'An introduction to the pwntools library.', tags: ['exploit dev', 'python', 'pwntools'] },
    { name: 'Offensive Security Intro', category: 'CTF', difficulty: 'Easy', description: 'An introduction to offensive security.', tags: ['red team', 'basics'] },
    { name: 'Defensive Security Intro', category: 'CTF', difficulty: 'Easy', description: 'An introduction to defensive security.', tags: ['blue team', 'basics'] },
    { name: 'Pyrat', category: 'CTF', difficulty: 'Easy', description: 'A Python-focused CTF.', tags: ['ctf', 'python'] },
    { name: 'Cheese CTF', category: 'CTF', difficulty: 'Easy', description: 'A fun, cheese-themed CTF.', tags: ['ctf', 'fun'] },
    { name: 'U.A. High School', category: 'CTF', difficulty: 'Easy', description: 'A My Hero Academia themed CTF.', tags: ['ctf', 'fun', 'anime'] },
    { name: 'Joomify', category: 'CTF', difficulty: 'Easy', description: 'A CTF focused on exploiting Joomla.', tags: ['ctf', 'web', 'joomla'] },
    { name: 'Critical', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on critical infrastructure.', tags: ['ctf', 'ics', 'scada'] },
    { name: 'Publisher', category: 'CTF', difficulty: 'Easy', description: 'A CTF focused on exploiting a publishing platform.', tags: ['ctf', 'web'] },
    { name: 'Eviction', category: 'CTF', difficulty: 'Easy', description: 'A CTF where you need to evict a user from a system.', tags: ['ctf', 'linux'] },
    { name: 'Become a Hacker', category: 'CTF', difficulty: 'Easy', description: 'A room to practice your hacking skills.', tags: ['ctf', 'basics'] },
    { name: 'WiseGuy', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on OSINT.', tags: ['ctf', 'osint'] },
    { name: 'mKingdom', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a medieval theme.', tags: ['ctf', 'fun'] },
    { name: 'How Websites Work', category: 'CTF', difficulty: 'Easy', description: 'Learn how websites work.', tags: ['web', 'basics'] },
    { name: 'CyberLens', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on forensics.', tags: ['ctf', 'forensics'] },
    { name: 'Security Principles', category: 'CTF', difficulty: 'Easy', description: 'Learn about security principles.', tags: ['security', 'basics'] },
    { name: 'TryHack3M: Bricks Heist', category: 'CTF', difficulty: 'Easy', description: 'A fun, heist-themed CTF.', tags: ['ctf', 'fun'] },
    { name: 'Creative', category: 'CTF', difficulty: 'Easy', description: 'A CTF that requires creative thinking.', tags: ['ctf', 'puzzle'] },
    { name: 'Putting it all together', category: 'CTF', difficulty: 'Easy', description: 'A CTF that combines skills from multiple domains.', tags: ['ctf', 'collection'] },
    { name: 'Probe', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on enumeration.', tags: ['ctf', 'recon'] },
    { name: 'Dreaming', category: 'CTF', difficulty: 'Easy', description: 'A surreal, dream-themed CTF.', tags: ['ctf', 'fun'] },
    { name: 'Pyramid Of Pain', category: 'CTF', difficulty: 'Easy', description: 'Learn about the Pyramid of Pain.', tags: ['blue team', 'threat intel'] },
    { name: 'The Witch\'s Cauldron', category: 'CTF', difficulty: 'Easy', description: 'A Halloween-themed CTF.', tags: ['ctf', 'fun', 'halloween'] },
    { name: 'Bulletproof Penguin', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on Linux hardening.', tags: ['ctf', 'linux', 'blue team'] },
    { name: 'Hijack', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on session hijacking.', tags: ['ctf', 'web'] },
    { name: 'Compiled', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on reverse engineering.', tags: ['ctf', 'reversing'] },
    { name: 'Super Secret Tip', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on OSINT.', tags: ['ctf', 'osint'] },
    { name: 'Lesson Learned?', category: 'CTF', difficulty: 'Easy', description: 'A CTF that teaches a valuable lesson.', tags: ['ctf', 'puzzle'] },
    { name: 'Grep', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on the grep command.', tags: ['ctf', 'linux', 'bash'] },
    { name: 'Red', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on red team techniques.', tags: ['ctf', 'red team'] },
    { name: 'Snapped "Phish"-ing Line', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on phishing.', tags: ['ctf', 'phishing'] },
    { name: 'Cat Pictures 2', category: 'CTF', difficulty: 'Easy', description: 'The second part of the Cat Pictures CTF.', tags: ['ctf', 'fun'] },
    { name: 'Flip', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on binary exploitation.', tags: ['ctf', 'exploit dev', 'reversing'] },
    { name: 'Valley!', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on web vulnerabilities.', tags: ['ctf', 'web'] },
    { name: 'Capture!', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on packet capture analysis.', tags: ['ctf', 'forensics', 'pcap'] },
    { name: 'Opacity', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on steganography.', tags: ['ctf', 'steganography'] },
    { name: 'LookBack', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on forensics.', tags: ['ctf', 'forensics'] },
    { name: 'Bugged', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on debugging.', tags: ['ctf', 'reversing'] },
    { name: 'GamingServer', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on exploiting a gaming server.', tags: ['ctf', 'gaming'] },
    { name: 'Confidential', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on data exfiltration.', tags: ['ctf', 'red team'] },
    { name: 'OverlayFS - CVE-2021-3493', category: 'CTF', difficulty: 'Easy', description: 'Exploit the OverlayFS vulnerability.', tags: ['cve', 'exploit', 'linux'] },
    { name: 'Fowsniff CTF', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on network traffic analysis.', tags: ['ctf', 'forensics', 'pcap'] },
    { name: 'AttackerKB', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on using the AttackerKB platform.', tags: ['ctf', 'recon'] },
    { name: 'Library', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on exploiting a library.', tags: ['ctf', 'linux'] },
    { name: 'Thompson', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on web vulnerabilities.', tags: ['ctf', 'web'] },
    { name: 'Simple CTF', category: 'CTF', difficulty: 'Easy', description: 'A simple CTF for beginners.', tags: ['ctf', 'basics'] },
    { name: 'Anonforce', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on anonymity.', tags: ['ctf', 'privacy'] },
    { name: 'Wgel CTF', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on web vulnerabilities.', tags: ['ctf', 'web'] },
    { name: 'Dav', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on WebDAV.', tags: ['ctf', 'web', 'webdav'] },
    { name: 'Ninja Skills', category: 'CTF', difficulty: 'Easy', description: 'A CTF to test your ninja skills.', tags: ['ctf', 'fun'] },
    { name: 'Ice', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on exploiting a specific service.', tags: ['ctf', 'windows'] },
    { name: 'The Cod Caper', category: 'CTF', difficulty: 'Easy', description: 'A fun, fish-themed CTF.', tags: ['ctf', 'fun'] },
    { name: 'Encryption - Crypto 101', category: 'CTF', difficulty: 'Easy', description: 'An introduction to encryption.', tags: ['crypto', 'basics'] },
    { name: 'Brooklyn Nine Nine', category: 'CTF', difficulty: 'Easy', description: 'A Brooklyn Nine-Nine themed CTF.', tags: ['ctf', 'fun', 'tv'] },
    { name: 'KOTH Food CTF', category: 'CTF', difficulty: 'Easy', description: 'A King of the Hill style CTF with a food theme.', tags: ['ctf', 'koth', 'fun'] },
    { name: 'Easy Peasy', category: 'CTF', difficulty: 'Easy', description: 'An easy CTF for beginners.', tags: ['ctf', 'basics'] },
    { name: 'Tony the Tiger', category: 'CTF', difficulty: 'Easy', description: 'A fun, cereal-themed CTF.', tags: ['ctf', 'fun'] },
    { name: 'CTF collection Vol.1', category: 'CTF', difficulty: 'Easy', description: 'The first volume of a collection of CTF challenges.', tags: ['ctf', 'collection'] },
    { name: 'Smag Grotto', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on exploiting a specific service.', tags: ['ctf', 'linux'] },
    { name: 'Couch', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on exploiting a CouchDB database.', tags: ['ctf', 'database', 'couchdb'] },
    { name: 'Source', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on source code analysis.', tags: ['ctf', 'reversing'] },
    { name: 'Gotta Catch\'em All!', category: 'CTF', difficulty: 'Easy', description: 'A Pokemon themed CTF.', tags: ['ctf', 'fun', 'pokemon'] },
    { name: 'kiba', category: 'CTF', difficulty: 'Easy', description: 'A Naruto themed CTF.', tags: ['ctf', 'fun', 'anime'] },
    { name: 'Poster', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on exploiting a poster creation service.', tags: ['ctf', 'web'] },
    { name: 'Chocolate Factory', category: 'CTF', difficulty: 'Easy', description: 'A Willy Wonka themed CTF.', tags: ['ctf', 'fun', 'movie'] },
    { name: 'Startup', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on exploiting a startup company.', tags: ['ctf', 'web'] },
    { name: 'Chill Hack', category: 'CTF', difficulty: 'Easy', description: 'A relaxing CTF for beginners.', tags: ['ctf', 'basics'] },
    { name: 'ColddBox: Easy', category: 'CTF', difficulty: 'Easy', description: 'An easy boot-to-root challenge.', tags: ['ctf', 'linux'] },
    { name: 'GLITCH', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on exploiting a glitch.', tags: ['ctf', 'puzzle'] },
    { name: 'All in One', category: 'CTF', difficulty: 'Easy', description: 'A CTF that combines skills from multiple domains.', tags: ['ctf', 'collection'] },
    { name: 'Archangel', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on web vulnerabilities.', tags: ['ctf', 'web'] },
    { name: 'Cyborg', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on exploiting a cyborg.', tags: ['ctf', 'fun'] },
    { name: 'Lunizz CTF', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on web vulnerabilities.', tags: ['ctf', 'web'] },
    { name: 'Badbyte', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on exploiting a specific service.', tags: ['ctf', 'linux'] },
    { name: 'Team', category: 'CTF', difficulty: 'Easy', description: 'A CTF that requires teamwork.', tags: ['ctf', 'team'] },
    { name: 'VulnNet: Node', category: 'CTF', difficulty: 'Easy', description: 'A Node.js focused VulnNet room.', tags: ['ctf', 'web', 'nodejs'] },
    { name: 'VulnNet: Internal', category: 'CTF', difficulty: 'Easy', description: 'An internal network focused VulnNet room.', tags: ['ctf', 'networking', 'pivoting'] },
    { name: 'Atlas', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on exploiting a specific service.', tags: ['ctf', 'linux'] },
    { name: 'VulnNet: Roasted', category: 'CTF', difficulty: 'Easy', description: 'A Kerberoasting focused VulnNet room.', tags: ['ctf', 'active directory', 'kerberoasting'] },
    { name: 'Cat Pictures', category: 'CTF', difficulty: 'Easy', description: 'A fun, cat-themed CTF.', tags: ['ctf', 'fun'] },
    { name: 'Mustacchio', category: 'CTF', difficulty: 'Easy', description: 'A CTF with a focus on exploiting a specific service.', tags: ['ctf', 'linux'] },
    { name: 'Introduction to Diango', category: 'Misc', difficulty: 'Easy', description: 'An introduction to the Django web framework.', tags: ['web', 'python', 'django'] },
    { name: 'Git Happens', category: 'Misc', difficulty: 'Easy', description: 'Learn about Git and how to exploit it.', tags: ['git', 'devops'] },
    { name: 'Splunk', category: 'Misc', difficulty: 'Easy', description: 'An introduction to Splunk.', tags: ['splunk', 'blue team'] },
    { name: 'Jupyter 101', category: 'Misc', difficulty: 'Easy', description: 'An introduction to Jupyter notebooks.', tags: ['python', 'data science'] },
    { name: 'Geolocating Images', category: 'Misc', difficulty: 'Easy', description: 'Learn how to geolocate images.', tags: ['osint', 'geolocation'] },
    { name: 'Tor', category: 'Misc', difficulty: 'Easy', description: 'An introduction to the Tor network.', tags: ['privacy', 'tor'] },
    { name: 'Intro to IoT Pentesting', category: 'Misc', difficulty: 'Easy', description: 'An introduction to IoT pentesting.', tags: ['iot', 'pentesting'] },
    { name: 'Printer Hacking 101', category: 'Misc', difficulty: 'Easy', description: 'An introduction to printer hacking.', tags: ['iot', 'pentesting'] },
    { name: 'Introduction to Flask', category: 'Misc', difficulty: 'Easy', description: 'An introduction to the Flask web framework.', tags: ['web', 'python', 'flask'] },
    { name: 'MITRE', category: 'Misc', difficulty: 'Easy', description: 'An introduction to the MITRE ATT&CK framework.', tags: ['blue team', 'threat intel'] },
    { name: 'magician', category: 'Misc', difficulty: 'Easy', description: 'A CTF with a focus on magic tricks.', tags: ['ctf', 'fun'] },
    { name: 'JPGChat', category: 'Misc', difficulty: 'Easy', description: 'A CTF with a focus on steganography.', tags: ['ctf', 'steganography'] },
    { name: 'Git and Crumpets', category: 'Misc', difficulty: 'Easy', description: 'A CTF with a focus on Git.', tags: ['ctf', 'git'] },
    { name: 'Hip Flask', category: 'Misc', difficulty: 'Easy', description: 'A CTF with a focus on Flask.', tags: ['ctf', 'web', 'python', 'flask'] },
    { name: 'The find command', category: 'Misc', difficulty: 'Easy', description: 'Learn how to use the find command in Linux.', tags: ['linux', 'bash'] },
    { name: '25 Days of Cyber Security', category: 'Special Events', difficulty: 'Easy', description: 'An advent calendar of cyber security challenges.', tags: ['ctf', 'collection', 'christmas'] },
    { name: 'Advent of Cyber 1 [2019]', category: 'Special Events', difficulty: 'Easy', description: 'The first Advent of Cyber event.', tags: ['ctf', 'collection', 'christmas'] },
    { name: 'Advent of Cyber 2 [2020]', category: 'Special Events', difficulty: 'Easy', description: 'The second Advent of Cyber event.', tags: ['ctf', 'collection', 'christmas'] },
    { name: 'Advent of Cyber 3 (2021)', category: 'Special Events', difficulty: 'Easy', description: 'The third Advent of Cyber event.', tags: ['ctf', 'collection', 'christmas'] },
    { name: 'Advent of Cyber 2022', category: 'Special Events', difficulty: 'Easy', description: 'The fourth Advent of Cyber event.', tags: ['ctf', 'collection', 'christmas'] },
    { name: 'Advent of Cyber 2023', category: 'Special Events', difficulty: 'Easy', description: 'The fifth Advent of Cyber event.', tags: ['ctf', 'collection', 'christmas'] },
    { name: 'Advent of Cyber 2024', category: 'Special Events', difficulty: 'Easy', description: 'The sixth Advent of Cyber event.', tags: ['ctf', 'collection', 'christmas'] },
    { name: 'Advent of Cyber \'23 Side Quest', category: 'Special Events', difficulty: 'Easy', description: 'A side quest for the Advent of Cyber 2023 event.', tags: ['ctf', 'collection', 'christmas'] },
    { name: 'Cyber Scotland 2021', category: 'Special Events', difficulty: 'Easy', description: 'A CTF from the Cyber Scotland 2021 event.', tags: ['ctf', 'collection'] },
    { name: 'Hacker of the Hill #1', category: 'Special Events', difficulty: 'Easy', description: 'The first Hacker of the Hill event.', tags: ['ctf', 'koth'] },
    { name: 'Learn and win prizes', category: 'Special Events', difficulty: 'Easy', description: 'A CTF with prizes.', tags: ['ctf', 'competition'] },
    { name: 'Learn and win prizes #2', category: 'Special Events', difficulty: 'Easy', description: 'The second CTF with prizes.', tags: ['ctf', 'competition'] },

    // --- Medium ---
    { name: 'Backtrack', category: 'CTF', difficulty: 'Medium', description: 'A CTF that requires backtracking and careful enumeration.', tags: ['ctf', 'web', 'reversing'] },
    { name: 'Extracted', category: 'CTF', difficulty: 'Medium', description: 'Analyze files and extract hidden information to progress.', tags: ['ctf', 'forensics', 'steganography'] },
    { name: 'The London Bridge', category: 'CTF', difficulty: 'Medium', description: 'A room focused on social engineering and OSINT.', tags: ['ctf', 'osint', 'social engineering'] },
    { name: 'Breakme', category: 'CTF', difficulty: 'Medium', description: 'A classic boot-to-root challenge requiring various skills.', tags: ['ctf', 'linux', 'privesc'] },
    { name: 'Block', category: 'CTF', difficulty: 'Medium', description: 'A CTF focused on blockchain and smart contract vulnerabilities.', tags: ['ctf', 'blockchain', 'web3'] },
    { name: 'APIWizards Breach', category: 'CTF', difficulty: 'Medium', description: 'Exploit a series of API vulnerabilities to breach the wizards.', tags: ['ctf', 'api', 'web'] },
    { name: 'New York Flankees', category: 'CTF', difficulty: 'Medium', description: 'A sports-themed CTF with a focus on web application security.', tags: ['ctf', 'web', 'sports'] },
    { name: 'Airplane', category: 'CTF', difficulty: 'Medium', description: 'A CTF involving the hacking of an airplane\'s infotainment system.', tags: ['ctf', 'iot', 'networking'] },
    { name: 'Profiles', category: 'CTF', difficulty: 'Medium', description: 'A CTF room that involves enumerating user profiles.', tags: ['ctf', 'osint', 'web'] },
    { name: 'Clocky', category: 'CTF', difficulty: 'Medium', description: 'A time-based CTF that requires precision and speed.', tags: ['ctf', 'web', 'timing attack'] },
    { name: 'Hack Smarter Security', category: 'CTF', difficulty: 'Medium', description: 'A CTF that challenges you to think smarter, not harder.', tags: ['ctf', 'logic', 'puzzle'] },
    { name: 'Kitty', category: 'CTF', difficulty: 'Medium', description: 'A cute-themed but challenging CTF.', tags: ['ctf', 'linux', 'web'] },
    { name: 'Umbrella', category: 'CTF', difficulty: 'Medium', description: 'A Resident Evil themed room from the Umbrella Corporation.', tags: ['ctf', 'windows', 'active directory'] },
    { name: 'Avenger', category: 'CTF', difficulty: 'Medium', description: 'An Avengers-themed CTF with multiple challenges.', tags: ['ctf', 'fun', 'web'] },
    { name: 'WhyHackMe', category: 'CTF', difficulty: 'Medium', description: 'A CTF that makes you question your hacking methodologies.', tags: ['ctf', 'metacognition'] },
    { name: 'Stealth', category: 'CTF', difficulty: 'Medium', description: 'A CTF that requires you to be stealthy and avoid detection.', tags: ['ctf', 'opsec', 'red team'] },
    { name: 'Hunt Me I: Payment Collectors', category: 'CTF', difficulty: 'Medium', description: 'A threat hunting CTF focused on payment collectors.', tags: ['ctf', 'blue team', 'threat hunting'] },
    { name: 'Hunt Me II: Typo Squatters', category: 'CTF', difficulty: 'Medium', description: 'A threat hunting CTF focused on typo squatting.', tags: ['ctf', 'blue team', 'threat hunting'] },
    { name: 'Athena', category: 'CTF', difficulty: 'Medium', description: 'A CTF with a Greek mythology theme.', tags: ['ctf', 'linux', 'web'] },
    { name: 'Crylo', category: 'CTF', difficulty: 'Medium', description: 'A CTF heavily focused on cryptography challenges.', tags: ['ctf', 'crypto'] },
    { name: 'Forgotten Implant', category: 'CTF', difficulty: 'Medium', description: 'A forensics challenge to find a forgotten malware implant.', tags: ['ctf', 'forensics', 'malware'] },
    { name: 'Race Conditions', category: 'CTF', difficulty: 'Medium', description: 'A CTF focused on exploiting race condition vulnerabilities.', tags: ['ctf', 'web', 'race condition'] },
    { name: 'Wonderland', category: 'CTF', difficulty: 'Medium', description: 'A whimsical Alice in Wonderland themed room focusing on Linux privilege escalation.', tags: ['ctf', 'linux', 'privesc', 'python'] },
    { name: 'Nax', category: 'CTF', difficulty: 'Medium', description: 'A medium-difficulty boot-to-root challenge.', tags: ['ctf', 'linux'] },
    { name: 'The Marketplace', category: 'CTF', difficulty: 'Medium', description: 'Exploit a web marketplace to find vulnerabilities.', tags: ['ctf', 'web', 'e-commerce'] },
    { name: 'Biohazard', category: 'CTF', difficulty: 'Medium', description: 'A Resident Evil themed room with a focus on malware analysis.', tags: ['ctf', 'malware', 'reversing'] },
    { name: 'Break it', category: 'CTF', difficulty: 'Medium', description: 'A challenge to break various security mechanisms.', tags: ['ctf', 'puzzle'] },
    { name: 'Willow', category: 'CTF', difficulty: 'Medium', description: 'A nature-themed CTF with a variety of challenges.', tags: ['ctf', 'linux', 'web'] },
    { name: 'HA Joker CTF', category: 'CTF', difficulty: 'Medium', description: 'A Joker-themed CTF that will test your sanity.', tags: ['ctf', 'fun', 'puzzle'] },
    { name: 'GoldenEye', category: 'CTF', difficulty: 'Medium', description: 'A James Bond themed CTF.', tags: ['ctf', 'fun', 'web'] },
    { name: 'StuxCTF', category: 'CTF', difficulty: 'Medium', description: 'A CTF inspired by the Stuxnet worm.', tags: ['ctf', 'ics', 'scada'] },
    { name: 'Boiler CTF', category: 'CTF', difficulty: 'Medium', description: 'A CTF focused on exploiting boilerplate code.', tags: ['ctf', 'web', 'reversing'] },
    { name: 'Weasel', category: 'CTF', difficulty: 'Medium', description: 'A tricky CTF that requires you to be as cunning as a weasel.', tags: ['ctf', 'linux'] },
    { name: 'Prioritise', category: 'CTF', difficulty: 'Medium', description: 'A CTF that tests your ability to prioritize targets.', tags: ['ctf', 'red team'] },
    { name: 'Boogeyman 1', category: 'CTF', difficulty: 'Medium', description: 'The first part of the Boogeyman series.', tags: ['ctf', 'horror'] },
    { name: 'Mr Robot CTE', category: 'CTF', difficulty: 'Medium', description: 'A CTF based on the Mr. Robot TV series, involving web, crypto and reversing.', tags: ['ctf', 'web', 'wordpress', 'reversing'] },
    { name: 'Unattended', category: 'CTF', difficulty: 'Medium', description: 'Exploit an unattended system to gain access.', tags: ['ctf', 'linux', 'automation'] },
    { name: 'Oday', category: 'CTF', difficulty: 'Medium', description: 'A CTF focused on finding and exploiting a zero-day vulnerability.', tags: ['ctf', 'exploit dev'] },
    { name: 'Develpy', category: 'Web', difficulty: 'Medium', description: 'Exploit a misconfigured Python web server to gain a foothold.', tags: ['web', 'python', 'file upload'] },
    { name: 'CTF collection Vol.2', category: 'CTF', difficulty: 'Medium', description: 'The second volume of a collection of CTF challenges.', tags: ['ctf', 'collection'] },
    { name: 'CMesS', category: 'CTF', difficulty: 'Medium', description: 'A messy CTF that requires careful enumeration.', tags: ['ctf', 'web'] },
    { name: 'Deja Vu', category: 'CTF', difficulty: 'Medium', description: 'A CTF where things might seem familiar.', tags: ['ctf', 'puzzle'] },
    { name: 'hackerNote', category: 'CTF', difficulty: 'Medium', description: 'A note-taking application with a vulnerability.', tags: ['ctf', 'web'] },
    { name: 'dogcat', category: 'CTF', difficulty: 'Medium', description: 'A CTF with a focus on exploiting a web application.', tags: ['ctf', 'web', 'lfi'] },
    { name: 'ConvertMyVideo', category: 'CTF', difficulty: 'Medium', description: 'Exploit a video conversion service.', tags: ['ctf', 'web', 'command injection'] },
    { name: 'KOTH Hackers', category: 'CTF', difficulty: 'Medium', description: 'A King of the Hill style CTF.', tags: ['ctf', 'koth'] },
    { name: 'Revenge', category: 'CTF', difficulty: 'Medium', description: 'A CTF where you get revenge on a system.', tags: ['ctf', 'linux'] },
    { name: 'harder', category: 'CTF', difficulty: 'Medium', description: 'A step up in difficulty from the easy rooms.', tags: ['ctf', 'challenge'] },
    { name: 'HaskHell', category: 'CTF', difficulty: 'Medium', description: 'A CTF focused on the Haskell programming language.', tags: ['ctf', 'haskell', 'reversing'] },
    { name: 'Undiscovered', category: 'CTF', difficulty: 'Medium', description: 'A CTF where you need to discover hidden vulnerabilities.', tags: ['ctf', 'recon'] },
    { name: 'Break Out The Cage', category: 'CTF', difficulty: 'Medium', description: 'A Nicolas Cage themed CTF.', tags: ['ctf', 'fun'] },
    { name: 'The Impossible Challenge', category: 'CTF', difficulty: 'Medium', description: 'A challenge that seems impossible at first.', tags: ['ctf', 'puzzle'] },
    { name: 'Looking Glass', category: 'CTF', difficulty: 'Medium', description: 'A CTF that involves looking through the looking glass.', tags: ['ctf', 'web'] },
    { name: 'Recovery', category: 'CTF', difficulty: 'Medium', description: 'A forensics challenge to recover lost data.', tags: ['ctf', 'forensics'] },
    { name: 'Relevant', category: 'CTF', difficulty: 'Medium', description: 'A CTF that is relevant to current events.', tags: ['ctf', 'osint'] },
    { name: 'Ghizer', category: 'CTF', difficulty: 'Medium', description: 'A medium-difficulty boot-to-root challenge.', tags: ['ctf', 'linux'] },
    { name: 'Mnemonic', category: 'CTF', difficulty: 'Medium', description: 'A CTF that involves mnemonics and memory.', tags: ['ctf', 'crypto'] },
    { name: 'Cooctus Stories', category: 'CTF', difficulty: 'Medium', description: 'A story-based CTF.', tags: ['ctf', 'narrative'] },
    { name: 'One Piece', category: 'CTF', difficulty: 'Medium', description: 'A One Piece themed CTF.', tags: ['ctf', 'fun', 'anime'] },
    { name: 'toc2', category: 'CTF', difficulty: 'Medium', description: 'The second part of the TOC series.', tags: ['ctf', 'collection'] },
    { name: 'NerdHerd', category: 'CTF', difficulty: 'Medium', description: 'A Chuck-themed CTF from the Nerd Herd.', tags: ['ctf', 'fun', 'tv'] },
    { name: 'Kubernetes Chall TDI 2020', category: 'CTF', difficulty: 'Medium', description: 'A Kubernetes challenge from TDI 2020.', tags: ['ctf', 'kubernetes', 'cloud'] },
    { name: 'The Server From Hell', category: 'CTF', difficulty: 'Medium', description: 'A CTF on a server that is a nightmare to work with.', tags: ['ctf', 'linux', 'sysadmin'] },
    { name: 'Jacob the Boss', category: 'CTF', difficulty: 'Medium', description: 'A CTF where you need to hack your boss.', tags: ['ctf', 'web'] },
    { name: 'Unbaked Pie', category: 'CTF', difficulty: 'Medium', description: 'A CTF with a Raspberry Pi theme.', tags: ['ctf', 'iot'] },
    { name: 'Bookstore', category: 'CTF', difficulty: 'Medium', description: 'Exploit a vulnerable online bookstore.', tags: ['ctf', 'web'] },
    { name: 'Overpass 3 - Hosting', category: 'CTF', difficulty: 'Medium', description: 'The third part of the Overpass series.', tags: ['ctf', 'collection'] },
    { name: 'battery', category: 'CTF', difficulty: 'Medium', description: 'A CTF with a focus on power and energy.', tags: ['ctf', 'iot'] },
    { name: 'Madeye\'s Castle', category: 'CTF', difficulty: 'Medium', description: 'A Harry Potter themed CTF.', tags: ['ctf', 'fun', 'harry potter'] },
    { name: 'En-pass', category: 'CTF', difficulty: 'Medium', description: 'A chess-themed CTF.', tags: ['ctf', 'fun', 'chess'] },
    { name: 'Sustah', category: 'CTF', difficulty: 'Medium', description: 'A medium-difficulty boot-to-root challenge.', tags: ['ctf', 'linux'] },
    { name: 'KaffeeSec - SoMeSINT', category: 'CTF', difficulty: 'Medium', description: 'A social media OSINT challenge.', tags: ['ctf', 'osint', 'social media'] },
    { name: 'Tokyo Ghoul', category: 'CTF', difficulty: 'Medium', description: 'A Tokyo Ghoul themed CTF.', tags: ['ctf', 'fun', 'anime'] },
    { name: 'Watcher', category: 'CTF', difficulty: 'Medium', description: 'A CTF where you are being watched.', tags: ['ctf', 'opsec'] },
    { name: 'broker', category: 'CTF', difficulty: 'Medium', description: 'A CTF focused on message brokers.', tags: ['ctf', 'networking'] },
    { name: 'Inferno', category: 'CTF', difficulty: 'Medium', description: 'A Dante\'s Inferno themed CTF.', tags: ['ctf', 'fun', 'literature'] },
    { name: 'VulnNet: dotpy', category: 'CTF', difficulty: 'Medium', description: 'A Python-focused VulnNet room.', tags: ['ctf', 'python', 'web'] },
    { name: 'Wekor', category: 'CTF', difficulty: 'Medium', description: 'A medium-difficulty boot-to-root challenge.', tags: ['ctf', 'linux'] },
    { name: 'pyLon', category: 'CTF', difficulty: 'Medium', description: 'A Python-focused CTF.', tags: ['ctf', 'python'] },
    { name: 'SafeZone', category: 'CTF', difficulty: 'Medium', description: 'A CTF where you need to find a safe zone.', tags: ['ctf', 'puzzle'] },
    { name: 'NahamStore', category: 'CTF', difficulty: 'Medium', description: 'A web application CTF from NahamCon.', tags: ['ctf', 'web', 'nahamcon'] },
    { name: 'Sweettooth Inc.', category: 'CTF', difficulty: 'Medium', description: 'A CTF with a sweet theme.', tags: ['ctf', 'fun'] },
    { name: 'Red Team OPSEC', category: 'CTF', difficulty: 'Medium', description: 'A CTF focused on Red Team operational security.', tags: ['ctf', 'red team', 'opsec'] },
    { name: 'CMSpit', category: 'CTF', difficulty: 'Medium', description: 'A CTF focused on exploiting a CMS.', tags: ['ctf', 'web', 'cms'] },
    { name: 'Super-Spam', category: 'CTF', difficulty: 'Medium', description: 'A CTF focused on analyzing spam emails.', tags: ['ctf', 'forensics', 'email'] },
    { name: 'That\'s The Ticket', category: 'CTF', difficulty: 'Medium', description: 'A CTF focused on exploiting a ticketing system.', tags: ['ctf', 'web'] },
    { name: 'Debug', category: 'CTF', difficulty: 'Medium', description: 'A CTF focused on debugging applications.', tags: ['ctf', 'reversing'] },
    { name: 'Red Stone One Carat', category: 'CTF', difficulty: 'Medium', description: 'A CTF with a Minecraft theme.', tags: ['ctf', 'fun', 'minecraft'] },
    { name: 'PaperCut: CVE-2023-27350', category: 'Misc', difficulty: 'Medium', description: 'Exploit a vulnerability in PaperCut print management software.', tags: ['cve', 'exploit', 'papercut'] },
    { name: 'Moniker Link (CVE-2024-21413)', category: 'Misc', difficulty: 'Medium', description: 'Exploit the Moniker Link vulnerability.', tags: ['cve', 'exploit', 'windows'] },
    { name: 'Threat Intel & Containment', category: 'Misc', difficulty: 'Medium', description: 'A room focused on threat intelligence and containment.', tags: ['blue team', 'threat intel'] },
    { name: 'Meltdown Explained', category: 'Misc', difficulty: 'Medium', description: 'Learn about the Meltdown vulnerability.', tags: ['hardware', 'exploit'] },
    { name: 'Linux Backdoors', category: 'Misc', difficulty: 'Medium', description: 'Learn about common Linux backdoors.', tags: ['linux', 'malware', 'persistence'] },
    { name: 'DLL HIJACKING', category: 'Misc', difficulty: 'Medium', description: 'Learn how to perform DLL hijacking.', tags: ['windows', 'exploit', 'dll hijacking'] },
    { name: 'DNS Manipulation', category: 'Misc', difficulty: 'Medium', description: 'Learn how to manipulate DNS records.', tags: ['networking', 'dns'] },
    { name: 'Wordpress: CVE-2021-29447', category: 'Misc', difficulty: 'Medium', description: 'Exploit a vulnerability in a WordPress plugin.', tags: ['cve', 'exploit', 'wordpress'] },
    { name: 'REvil Corp', category: 'Misc', difficulty: 'Medium', description: 'A room based on the REvil ransomware group.', tags: ['malware', 'ransomware'] },
    { name: 'Conti', category: 'Misc', difficulty: 'Medium', description: 'A room based on the Conti ransomware group.', tags: ['malware', 'ransomware'] },
    { name: 'Linux PrivEsc', category: 'Linux', difficulty: 'Medium', description: 'Learn a variety of ways to escalate privileges on Linux.', tags: ['linux', 'privesc', 'escalation'] },
    { name: 'Linux Privesc Arena', category: 'Linux', difficulty: 'Medium', description: 'Practice your Linux privilege escalation skills in a game-like environment.', tags: ['linux', 'privesc', 'ctf'] },
    { name: 'Windows PrivEsc Arena', category: 'Windows', difficulty: 'Medium', description: 'Practice your Windows privilege escalation skills.', tags: ['windows', 'privesc', 'escalation'] },
    { name: 'Post-Exploitation Basics', category: 'Active Directory', difficulty: 'Medium', description: 'Learn the basics of what to do after you have a foothold in Active Directory.', tags: ['active directory', 'post-exploit'] },
    { name: 'Buffer Overflow Prep', category: 'Exploit Development', difficulty: 'Medium', description: 'Learn the basics of x86 buffer overflows, a must for OSCP.', tags: ['exploit dev', 'buffer overflow', 'oscp'] },
    { name: 'Gatekeeper', category: 'Exploit Development', difficulty: 'Medium', description: 'A CTF style room to practice your buffer overflow skills.', tags: ['exploit dev', 'buffer overflow', 'ctf'] },
    { name: 'Reverse Engineering', category: 'Reverse Engineering', difficulty: 'Medium', description: 'An introduction to the concepts of reverse engineering.', tags: ['reversing', 'assembly'] },
    { name: 'REloaded', category: 'Reverse Engineering', difficulty: 'Medium', description: 'Practice your reversing skills on a variety of challenges.', tags: ['reversing', 'ctf'] },
    { name: 'Volatility', category: 'Forensics', difficulty: 'Medium', description: 'Learn how to use the Volatility framework for memory analysis.', tags: ['forensics', 'memory', 'volatility'] },
    { name: 'Disk Analysis & Autopsy', category: 'Forensics', difficulty: 'Medium', description: 'Learn how to analyze a disk image using Autopsy.', tags: ['forensics', 'disk', 'autopsy'] },
    { name: 'Hypervisor Internals', category: 'Basics', difficulty: 'Medium', description: 'Learn about hypervisor internals.', tags: ['virtualization', 'reversing'] },
    { name: 'Splunk: Exploring SPL', category: 'Basics', difficulty: 'Medium', description: 'Learn how to use the Splunk Search Processing Language.', tags: ['splunk', 'blue team'] },
    { name: 'ParrotPost: Phishing Analysis', category: 'Basics', difficulty: 'Medium', description: 'Analyze a phishing email.', tags: ['phishing', 'forensics'] },
    { name: 'Threat Intelligence for SOC', category: 'Basics', difficulty: 'Medium', description: 'Learn about threat intelligence for a Security Operations Center.', tags: ['blue team', 'threat intel'] },
    { name: 'UltraTech', category: 'Recon', difficulty: 'Medium', description: 'A room to practice your OSINT skills.', tags: ['osint', 'recon'] },
    { name: 'Red Team Recon', category: 'Recon', difficulty: 'Medium', description: 'Learn how to perform reconnaissance as a red teamer.', tags: ['red team', 'recon'] },
    { name: 'Searchlight - IMINT', category: 'Recon', difficulty: 'Medium', description: 'A room to practice your image intelligence skills.', tags: ['osint', 'imint'] },
    { name: 'Intro PoC Scripting', category: 'Scripting', difficulty: 'Medium', description: 'Learn how to write proof-of-concept scripts.', tags: ['scripting', 'exploit dev'] },
    { name: 'Peak Hill', category: 'Scripting', difficulty: 'Medium', description: 'A room to practice your scripting skills.', tags: ['scripting', 'ctf'] },
    { name: 'Learn Rust', category: 'Scripting', difficulty: 'Medium', description: 'Learn the Rust programming language.', tags: ['rust', 'scripting'] },
    { name: 'TShark', category: 'Tooling', difficulty: 'Medium', description: 'Learn how to use the TShark command-line network protocol analyzer.', tags: ['tshark', 'networking', 'forensics'] },
    { name: 'K8s Runtime Security', category: 'Container Security', difficulty: 'Medium', description: 'Learn about Kubernetes runtime security.', tags: ['kubernetes', 'cloud', 'security'] },
    { name: 'K8s Best Security Practices', category: 'Container Security', difficulty: 'Medium', description: 'Learn about Kubernetes security best practices.', tags: ['kubernetes', 'cloud', 'security'] },
    { name: 'Crack The Hash Level 2', category: 'Cryptography', difficulty: 'Medium', description: 'A room to practice your hash cracking skills.', tags: ['crypto', 'hash cracking'] },
    { name: 'Unstable Twin', category: 'Steganography', difficulty: 'Medium', description: 'A room to practice your steganography skills.', tags: ['steganography', 'forensics'] },
    { name: 'Microservices Architectures', category: 'Web', difficulty: 'Medium', description: 'Learn about microservices architectures.', tags: ['web', 'devops'] },
    { name: 'NoSQL Injection', category: 'Web', difficulty: 'Medium', description: 'Learn how to exploit NoSQL injection vulnerabilities.', tags: ['web', 'nosql', 'database'] },
    { name: 'HTTP Request Smuggling', category: 'Web', difficulty: 'Medium', description: 'Learn how to perform HTTP request smuggling.', tags: ['web', 'request smuggling'] },
    { name: 'SSTI', category: 'Web', difficulty: 'Medium', description: 'Learn how to exploit Server-Side Template Injection vulnerabilities.', tags: ['web', 'ssti'] },
    { name: 'Linux Incident Surface', category: 'Forensics', difficulty: 'Medium', description: 'Learn about the Linux incident surface.', tags: ['linux', 'forensics', 'blue team'] },
    { name: 'IR Playbooks', category: 'Forensics', difficulty: 'Medium', description: 'Learn how to create incident response playbooks.', tags: ['forensics', 'blue team'] },
    { name: 'Windows Applications Forensics', category: 'Forensics', difficulty: 'Medium', description: 'Learn how to perform forensics on Windows applications.', tags: ['windows', 'forensics'] },
    { name: 'Memory Forensics', category: 'Forensics', difficulty: 'Medium', description: 'Learn how to perform memory forensics.', tags: ['forensics', 'memory'] },
    { name: 'Linux Server Forensics', category: 'Forensics', difficulty: 'Medium', description: 'Learn how to perform forensics on a Linux server.', tags: ['linux', 'forensics'] },
    { name: 'JVM Reverse Engineering', category: 'Reverse Engineering', difficulty: 'Medium', description: 'Learn how to reverse engineer Java Virtual Machine bytecode.', tags: ['reversing', 'java'] },
    { name: 'CC: Radare2', category: 'Reverse Engineering', difficulty: 'Medium', description: 'A room to practice your Radare2 skills.', tags: ['reversing', 'radare2', 'tooling'] },
    { name: 'CC: Ghidra', category: 'Reverse Engineering', difficulty: 'Medium', description: 'A room to practice your Ghidra skills.', tags: ['reversing', 'ghidra', 'tooling'] },
    { name: 'Classic Passwd', category: 'Reverse Engineering', difficulty: 'Medium', description: 'A classic reverse engineering challenge.', tags: ['reversing', 'ctf'] },
    { name: 'Mobile Malware Analysis', category: 'Malware Analysis', difficulty: 'Medium', description: 'Learn how to analyze mobile malware.', tags: ['malware', 'android', 'reversing'] },
    { name: 'Carnage', category: 'Malware Analysis', difficulty: 'Medium', description: 'A room to practice your malware analysis skills.', tags: ['malware', 'reversing'] },
    { name: 'Linux Agency', category: 'PrivEsc', difficulty: 'Medium', description: 'A room to practice your Linux privilege escalation skills.', tags: ['linux', 'privesc'] },
    { name: 'Windows Incident Surface', category: 'Windows', difficulty: 'Medium', description: 'Learn about the Windows incident surface.', tags: ['windows', 'forensics', 'blue team'] },
    { name: 'Registry Persistence Detection', category: 'Windows', difficulty: 'Medium', description: 'Learn how to detect persistence in the Windows registry.', tags: ['windows', 'forensics', 'blue team'] },
    { name: 'Investigating Windows', category: 'Windows', difficulty: 'Medium', description: 'Learn how to investigate Windows systems.', tags: ['windows', 'forensics'] },
    { name: 'Investigating Windows 2.0', category: 'Windows', difficulty: 'Medium', description: 'The second part of the Investigating Windows series.', tags: ['windows', 'forensics'] },
    { name: 'Investigating Windows 3.x', category: 'Windows', difficulty: 'Medium', description: 'The third part of the Investigating Windows series.', tags: ['windows', 'forensics'] },
    { name: 'Active Directory Hardening', category: 'Active Directory', difficulty: 'Medium', description: 'Learn how to harden an Active Directory environment.', tags: ['active directory', 'blue team'] },
    { name: 'h4cked', category: 'PCAP Analysis', difficulty: 'Medium', description: 'Analyze network traffic to find out what happened.', tags: ['pcap', 'forensics', 'networking'] },
    { name: 'Chronicle', category: 'Buffer Overflow', difficulty: 'Medium', description: 'A room to practice your buffer overflow skills.', tags: ['exploit dev', 'buffer overflow', 'ctf'] },
    { name: 'Linux Process Analysis', category: 'Linux', difficulty: 'Medium', description: 'Learn how to analyze Linux processes.', tags: ['linux', 'forensics'] },

    // --- Hard ---
    { name: 'x86 Architecture Overview', category: 'Basics', difficulty: 'Hard', description: 'An overview of the x86 architecture.', tags: ['reversing', 'assembly'] },
    { name: 'Dumping Router Firmware', category: 'Networking', difficulty: 'Hard', description: 'Learn how to dump router firmware.', tags: ['iot', 'reversing'] },
    { name: 'Cluster Hardening', category: 'Container Security', difficulty: 'Hard', description: 'Learn how to harden a Kubernetes cluster.', tags: ['kubernetes', 'cloud', 'security'] },
    { name: 'Breaking RSA', category: 'Cryptography', difficulty: 'Hard', description: 'Learn how to break RSA encryption.', tags: ['crypto', 'rsa'] },
    { name: 'Cicada-3301 Vol:1', category: 'Cryptography', difficulty: 'Hard', description: 'The first volume of the Cicada 3301 challenge.', tags: ['crypto', 'puzzle'] },
    { name: 'Advanced SQL Injection', category: 'Web', difficulty: 'Hard', description: 'Learn advanced SQL injection techniques.', tags: ['web', 'sqli'] },
    { name: 'HTTP/2 Request Smuggling', category: 'Web', difficulty: 'Hard', description: 'Learn how to perform HTTP/2 request smuggling.', tags: ['web', 'request smuggling'] },
    { name: 'Servidae: Log Analysis in ELK', category: 'Forensics', difficulty: 'Hard', description: 'Analyze logs in an ELK stack.', tags: ['forensics', 'elk', 'blue team'] },
    { name: 'Digital Forensics Case B4DM755', category: 'Forensics', difficulty: 'Hard', description: 'A hard digital forensics case.', tags: ['forensics', 'case'] },
    { name: 'Windows x64 Assembly', category: 'Reverse Engineering', difficulty: 'Hard', description: 'Learn x64 assembly for Windows.', tags: ['reversing', 'assembly', 'windows'] },
    { name: 'Aster', category: 'Reverse Engineering', difficulty: 'Hard', description: 'A hard reversing challenge.', tags: ['reversing', 'ctf'] },
    { name: 'Dunkle Materie', category: 'Malware Analysis', difficulty: 'Hard', description: 'A hard malware analysis challenge.', tags: ['malware', 'reversing'] },
    { name: 'Sudo Buffer Overflow', category: 'Exploit Development', difficulty: 'Hard', description: 'Exploit a buffer overflow in sudo.', tags: ['exploit dev', 'buffer overflow', 'linux'] },
    { name: 'Breaching Active Directory', category: 'Active Directory', difficulty: 'Hard', description: 'A hard Active Directory challenge.', tags: ['active directory', 'red team'] },
    { name: 'USTOUN', category: 'Active Directory', difficulty: 'Hard', description: 'A hard Active Directory challenge.', tags: ['active directory', 'red team'] },
    { name: 'Enterprise', category: 'Active Directory', difficulty: 'Hard', description: 'A challenging room simulating a full enterprise environment.', tags: ['active directory', 'red team'] },
    { name: 'RazorBlack', category: 'Active Directory', difficulty: 'Hard', description: 'A hard Active Directory challenge.', tags: ['active directory', 'red team'] },
    { name: 'CCT2019', category: 'CTF', difficulty: 'Hard', description: 'A CTF from CCT2019.', tags: ['ctf', 'collection'] },
    { name: 'Cold VVars', category: 'CTF', difficulty: 'Hard', description: 'A Cold War themed CTF.', tags: ['ctf', 'history'] },
    { name: 'Metamorphosis', category: 'CTF', difficulty: 'Hard', description: 'A CTF that changes as you progress.', tags: ['ctf', 'dynamic'] },
    { name: 'SQHell', category: 'CTF', difficulty: 'Hard', description: 'A CTF with a focus on advanced SQL injection.', tags: ['ctf', 'web', 'sqli'] },
    { name: 'Fortress', category: 'CTF', difficulty: 'Hard', description: 'A CTF where you need to breach a fortress.', tags: ['ctf', 'red team'] },
    { name: 'CyberCrafted', category: 'CTF', difficulty: 'Hard', description: 'A CTF with a focus on crafting exploits.', tags: ['ctf', 'exploit dev'] },
    { name: 'Road', category: 'CTF', difficulty: 'Hard', description: 'A CTF with a road trip theme.', tags: ['ctf', 'fun'] },
    { name: 'CERTain Doom', category: 'CTF', difficulty: 'Hard', description: 'A CTF from a CERT.', tags: ['ctf', 'cert'] },
    { name: 'Capture Returns', category: 'CTF', difficulty: 'Hard', description: 'The return of the Capture CTF.', tags: ['ctf', 'collection'] },
    { name: 'Chrome', category: 'CTF', difficulty: 'Hard', description: 'A CTF focused on exploiting the Chrome browser.', tags: ['ctf', 'browser', 'exploit'] },
    { name: 'Reset', category: 'CTF', difficulty: 'Hard', description: 'A CTF where you need to reset a system.', tags: ['ctf', 'puzzle'] },
    { name: 'Motunui', category: 'CTF', difficulty: 'Hard', description: 'A Moana themed CTF.', tags: ['ctf', 'fun', 'disney'] },
    { name: 'Spring', category: 'CTF', difficulty: 'Hard', description: 'A CTF focused on the Spring framework.', tags: ['ctf', 'web', 'spring'] },
    { name: 'Brainpan 1', category: 'CTF', difficulty: 'Hard', description: 'A classic buffer overflow challenge.', tags: ['ctf', 'exploit dev', 'buffer overflow'] },
    { name: 'Borderlands', category: 'CTF', difficulty: 'Hard', description: 'A Borderlands themed CTF.', tags: ['ctf', 'fun', 'gaming'] },
    { name: 'hcon Christmas CTF', category: 'CTF', difficulty: 'Hard', description: 'A Christmas themed CTF from hcon.', tags: ['ctf', 'fun', 'christmas'] },
    { name: 'Daily Bugle', category: 'CTF', difficulty: 'Hard', description: 'Hack into the Daily Bugle newspaper to find sensitive information.', tags: ['ctf', 'web', 'sqli', 'joomla', 'privesc'] },
    { name: 'Retro', category: 'CTF', difficulty: 'Hard', description: 'A retro-themed CTF.', tags: ['ctf', 'fun', 'retro'] },
    { name: 'Jeff', category: 'CTF', difficulty: 'Hard', description: 'A hard boot-to-root challenge.', tags: ['ctf', 'linux'] },
    { name: 'Racetrack Bank', category: 'CTF', difficulty: 'Hard', description: 'Exploit a vulnerable online bank.', tags: ['ctf', 'web', 'finance'] },
    { name: 'Dave\'s Blog', category: 'CTF', difficulty: 'Hard', description: 'Exploit a vulnerable blog.', tags: ['ctf', 'web'] },
    { name: 'CherryBlossom', category: 'CTF', difficulty: 'Hard', description: 'A CTF with a Japanese theme.', tags: ['ctf', 'fun', 'japan'] },
    { name: 'Iron Corp', category: 'CTF', difficulty: 'Hard', description: 'A CTF from Iron Corp.', tags: ['ctf', 'red team'] },
    { name: 'GameBuzz', category: 'CTF', difficulty: 'Hard', description: 'A CTF focused on exploiting a gaming website.', tags: ['ctf', 'web', 'gaming'] },
    { name: 'Misguided Ghosts', category: 'CTF', difficulty: 'Hard', description: 'A CTF with a ghostly theme.', tags: ['ctf', 'fun', 'horror'] },
    { name: 'Theseus', category: 'CTF', difficulty: 'Hard', description: 'A CTF with a Greek mythology theme.', tags: ['ctf', 'fun', 'mythology'] },
    { name: 'Internal', category: 'CTF', difficulty: 'Hard', description: 'A CTF focused on internal network pivoting.', tags: ['ctf', 'red team', 'pivoting'] },
    { name: 'Year of the Dog', category: 'CTF', difficulty: 'Hard', description: 'A CTF for the Year of the Dog.', tags: ['ctf', 'fun', 'zodiac'] },
    { name: 'You\'re in a cave', category: 'CTF', difficulty: 'Hard', description: 'A text-based adventure CTF.', tags: ['ctf', 'fun', 'text adventure'] },
    { name: 'Year of the Owl', category: 'CTF', difficulty: 'Hard', description: 'A CTF for the Year of the Owl.', tags: ['ctf', 'fun', 'zodiac'] },
    { name: 'Year of the Pig', category: 'CTF', difficulty: 'Hard', description: 'A CTF for the Year of the Pig.', tags: ['ctf', 'fun', 'zodiac'] },
    { name: 'envizon', category: 'CTF', difficulty: 'Hard', description: 'A CTF focused on the envizon tool.', tags: ['ctf', 'tooling'] },
    { name: 'Carpe Diem 1', category: 'CTF', difficulty: 'Hard', description: 'The first part of the Carpe Diem series.', tags: ['ctf', 'collection'] },
    { name: 'Ra', category: 'CTF', difficulty: 'Hard', description: 'An Egyptian mythology themed CTF.', tags: ['ctf', 'fun', 'mythology'] },
    { name: 'Year of the Fox', category: 'CTF', difficulty: 'Hard', description: 'A CTF for the Year of the Fox.', tags: ['ctf', 'fun', 'zodiac'] },
    { name: 'For Business Reasons', category: 'CTF', difficulty: 'Hard', description: 'A CTF with a corporate theme.', tags: ['ctf', 'red team'] },
    { name: 'Anonymous Playground', category: 'CTF', difficulty: 'Hard', description: 'A playground for anonymous hackers.', tags: ['ctf', 'fun'] },
    { name: 'Uranium CTF', category: 'CTF', difficulty: 'Hard', description: 'A CTF with a nuclear theme.', tags: ['ctf', 'fun'] },
    { name: 'Year of the Jellyfish', category: 'CTF', difficulty: 'Hard', description: 'A CTF for the Year of the Jellyfish.', tags: ['ctf', 'fun', 'zodiac'] },
    { name: 'Rocket', category: 'CTF', difficulty: 'Hard', description: 'A CTF with a space theme.', tags: ['ctf', 'fun', 'space'] },
    { name: 'Squid Game', category: 'CTF', difficulty: 'Hard', description: 'A Squid Game themed CTF.', tags: ['ctf', 'fun', 'tv'] },
    { name: 'EnterPrize', category: 'CTF', difficulty: 'Hard', description: 'A CTF with a Star Trek theme.', tags: ['ctf', 'fun', 'tv'] },
    { name: 'Different CTF', category: 'CTF', difficulty: 'Hard', description: 'A CTF that is different from the rest.', tags: ['ctf', 'puzzle'] },
    { name: 'VulnNet: dotjar', category: 'CTF', difficulty: 'Hard', description: 'A Java-focused VulnNet room.', tags: ['ctf', 'java', 'web'] },
    { name: 'M4tr1x: Exit Denied', category: 'CTF', difficulty: 'Hard', description: 'A Matrix themed CTF.', tags: ['ctf', 'fun', 'movie'] },
    { name: 'Shaker', category: 'CTF', difficulty: 'Hard', description: 'A hard boot-to-root challenge.', tags: ['ctf', 'linux'] },
    { name: 'Confluence CVE-2023-22515', category: 'Misc', difficulty: 'Hard', description: 'Exploit a vulnerability in Confluence.', tags: ['cve', 'exploit', 'confluence'] },
    { name: 'GitLab CVE-2023-7028', category: 'Misc', difficulty: 'Hard', description: 'Exploit a vulnerability in GitLab.', tags: ['cve', 'exploit', 'gitlab'] },
    { name: 'Cactus', category: 'Misc', difficulty: 'Hard', description: 'A hard boot-to-root challenge.', tags: ['ctf', 'linux'] },
    { name: 'Looney Tunables', category: 'Misc', difficulty: 'Hard', description: 'Exploit the Looney Tunables vulnerability.', tags: ['cve', 'exploit', 'linux'] },
    { name: 'CVE-2023-38408', category: 'Misc', difficulty: 'Hard', description: 'Exploit a vulnerability in OpenSSH.', tags: ['cve', 'exploit', 'ssh'] },
    { name: 'tomghost', category: 'Misc', difficulty: 'Hard', description: 'Exploit the TomGhost vulnerability.', tags: ['cve', 'exploit', 'tomcat'] },
    { name: 'Attacking ICS Plant #1', category: 'Misc', difficulty: 'Hard', description: 'The first part of a series on attacking ICS plants.', tags: ['ics', 'scada'] },
    { name: 'Attacking ICS Plant #2', category: 'Misc', difficulty: 'Hard', description: 'The second part of a series on attacking ICS plants.', tags: ['ics', 'scada'] },
    { name: 'Baron Samedit', category: 'Misc', difficulty: 'Hard', description: 'Exploit the Baron Samedit vulnerability.', tags: ['cve', 'exploit', 'linux'] },
    { name: 'CVE-2021-41773/42013', category: 'Misc', difficulty: 'Hard', description: 'Exploit vulnerabilities in Apache.', tags: ['cve', 'exploit', 'apache'] },
    { name: 'Binary Heaven', category: 'Misc', difficulty: 'Hard', description: 'A CTF with a focus on binary exploitation.', tags: ['ctf', 'exploit dev', 'reversing'] },
    { name: 'Polkit: CVE-2021-3560', category: 'Misc', difficulty: 'Hard', description: 'Exploit a vulnerability in Polkit.', tags: ['cve', 'exploit', 'linux'] },
    { name: 'Linux Function Hooking', category: 'Misc', difficulty: 'Hard', description: 'Learn how to hook functions in Linux.', tags: ['linux', 'reversing'] },
    { name: 'Dirty Pipe: CVE-2022-0847', category: 'Misc', difficulty: 'Hard', description: 'Exploit the Dirty Pipe vulnerability.', tags: ['cve', 'exploit', 'linux'] },
    { name: 'Solar, exploiting log4j', category: 'Misc', difficulty: 'Hard', description: 'Exploit the Log4j vulnerability.', tags: ['cve', 'exploit', 'log4j'] },

    // --- Insane ---
    { name: 'Frosteau Busy with Vim', category: 'CTF', difficulty: 'Insane', description: 'An insane Vim-based challenge.', tags: ['ctf', 'vim', 'puzzle'] }
];

document.addEventListener('DOMContentLoaded', () => {
    const dashboardView = document.getElementById('dashboard-view');
    const resultsView = document.getElementById('results-view');
    
    const categorySelect = document.getElementById('category');
    const difficultySelect = document.getElementById('difficulty');
    const exploreBtn = document.getElementById('explore-btn');
    const backBtn = document.getElementById('back-btn');

    const initialRoomList = document.getElementById('initial-room-list');
    const initialRoomCount = document.getElementById('initial-room-count');
    
    const resultsRoomList = document.getElementById('results-room-list');
    const resultsRoomCount = document.getElementById('results-room-count');
    const noResults = document.getElementById('no-results');

    const modal = document.getElementById('room-modal');
    const modalOverlay = document.getElementById('modal-overlay');
    const modalCloseBtn = document.getElementById('modal-close-btn');

    const categoryChartCtx = document.getElementById('categoryChart').getContext('2d');
    const difficultyChartCtx = document.getElementById('difficultyChart').getContext('2d');

    let categoryChart, difficultyChart;

    const getUrlFriendlyName = (name) => name.toLowerCase().replace(/ /g, '').replace(/[^\w-]+/g, '');

    const difficultyColors = {
        'Intro': 'rgba(75, 192, 192, 0.7)',
        'Easy': 'rgba(153, 204, 102, 0.7)',
        'Medium': 'rgba(255, 206, 86, 0.7)',
        'Hard': 'rgba(255, 99, 132, 0.7)',
        'Insane': 'rgba(153, 102, 255, 0.7)',
    };

    const openModal = (room) => {
        document.getElementById('modal-title').textContent = room.name;
        document.getElementById('modal-category-difficulty').textContent = `${room.category} • ${room.difficulty}`;
        document.getElementById('modal-description').textContent = room.description;
        document.getElementById('modal-link').href = `https://tryhackme.com/room/${getUrlFriendlyName(room.name)}`;
        
        const tagsContainer = document.getElementById('modal-tags');
        tagsContainer.innerHTML = '';
        room.tags.forEach(tag => {
            const tagElement = document.createElement('span');
            tagElement.className = 'bg-gray-200 text-gray-700 text-xs font-semibold mr-2 px-2.5 py-0.5 rounded-full';
            tagElement.textContent = tag;
            tagsContainer.appendChild(tagElement);
        });

        modal.classList.remove('hidden');
        document.body.classList.add('overflow-hidden');
        setTimeout(() => {
            modalOverlay.classList.remove('opacity-0');
            document.getElementById('modal-content').classList.remove('opacity-0', 'scale-95');
        }, 10);
    };

    const closeModal = () => {
        modalOverlay.classList.add('opacity-0');
        document.getElementById('modal-content').classList.add('opacity-0', 'scale-95');
        setTimeout(() => {
            modal.classList.add('hidden');
            document.body.classList.remove('overflow-hidden');
        }, 300);
    };

    const renderRooms = (roomsToRender, containerElement, countElement) => {
        containerElement.innerHTML = '';
        if (roomsToRender.length === 0 && containerElement.id === 'results-room-list') {
            noResults.classList.remove('hidden');
        } else {
            noResults.classList.add('hidden');
        }

        roomsToRender.forEach((room, index) => {
            const roomCard = document.createElement('div');
            roomCard.className = 'room-card block bg-white p-4 rounded-lg shadow-md border border-gray-200/80 cursor-pointer opacity-0';
            roomCard.style.animation = `fadeIn 0.5s ease-out ${index * 0.05}s forwards`;
            roomCard.dataset.roomName = room.name;
            
            const difficultyColor = difficultyColors[room.difficulty] || 'rgba(201, 203, 207, 0.7)';
            roomCard.innerHTML = `
                <h3 class="font-bold text-lg text-gray-800 truncate pointer-events-none">${room.name}</h3>
                <div class="flex justify-between items-center mt-3 pointer-events-none">
                    <span class="text-sm text-gray-500">${room.category}</span>
                    <span class="text-sm font-semibold px-2 py-1 rounded" style="background-color: ${difficultyColor}; color: #333">${room.difficulty}</span>
                </div>
            `;
            containerElement.appendChild(roomCard);
        });

        if (countElement) {
            countElement.textContent = `${roomsToRender.length} rooms found`;
        }
    };

    document.body.addEventListener('click', (e) => {
        const card = e.target.closest('.room-card');
        if (card) {
            const roomName = card.dataset.roomName;
            const roomData = roomsData.find(r => r.name === roomName);
            if (roomData) {
                openModal(roomData);
            }
        }
    });

    const populateFilters = () => {
        const categories = ['all', ...new Set(roomsData.map(r => r.category).sort())];
        const difficulties = ['all', 'Intro', 'Easy', 'Medium', 'Hard', 'Insane'];
        
        categorySelect.innerHTML = '';
        difficultySelect.innerHTML = '';

        categories.forEach(cat => {
            const option = document.createElement('option');
            option.value = cat;
            option.textContent = cat.charAt(0).toUpperCase() + cat.slice(1);
            categorySelect.appendChild(option);
        });

        difficulties.forEach(diff => {
            if (roomsData.some(r => r.difficulty === diff) || diff === 'all') {
                const option = document.createElement('option');
                option.value = diff;
                option.textContent = diff.charAt(0).toUpperCase() + diff.slice(1);
                difficultySelect.appendChild(option);
            }
        });
    };

    const createCharts = () => {
        const categoryCounts = roomsData.reduce((acc, room) => {
            acc[room.category] = (acc[room.category] || 0) + 1;
            return acc;
        }, {});

        const difficultyCounts = roomsData.reduce((acc, room) => {
            acc[room.difficulty] = (acc[room.difficulty] || 0) + 1;
            return acc;
        }, {});

        const sortedDifficulties = Object.entries(difficultyCounts).sort((a,b) => {
            const order = { 'Intro': 0, 'Easy': 1, 'Medium': 2, 'Hard': 3, 'Insane': 4 };
            return order[a[0]] - order[b[0]];
        });

        if (categoryChart) categoryChart.destroy();
        categoryChart = new Chart(categoryChartCtx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(categoryCounts),
                datasets: [{
                    data: Object.values(categoryCounts),
                    backgroundColor: ['#77A88D', '#A1C3A1', '#C5DDBA', '#E8F2E1', '#E5D9C8', '#C3B5A5', '#A99985', '#8A7E6F', '#6B635B', '#564E4A', '#413A37', '#2C2624', '#171211'],
                    borderColor: '#FDFBF8',
                    borderWidth: 2
                }]
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false, 
                plugins: { 
                    legend: { 
                        position: 'bottom', 
                        labels: { font: { size: 10 } } 
                    }
                },
                animation: {
                    animateScale: true,
                    animateRotate: true
                }
            }
        });

        if (difficultyChart) difficultyChart.destroy();
        difficultyChart = new Chart(difficultyChartCtx, {
            type: 'bar',
            data: {
                labels: sortedDifficulties.map(d => d[0]),
                datasets: [{
                    label: 'Rooms by Difficulty',
                    data: sortedDifficulties.map(d => d[1]),
                    backgroundColor: sortedDifficulties.map(d => difficultyColors[d[0]] || 'rgba(201, 203, 207, 0.7)'),
                    borderWidth: 0
                }]
            },
            options: { 
                indexAxis: 'y', 
                responsive: true, 
                maintainAspectRatio: false, 
                plugins: { legend: { display: false } }, 
                scales: { x: { beginAtZero: true } },
                animation: {
                    duration: 1000,
                    easing: 'easeOutQuart'
                }
            }
        });
    };
    
    const handleViewChange = () => {
        const hash = window.location.hash;
        if (hash.startsWith('#results')) {
            const params = new URLSearchParams(hash.split('?')[1]);
            const category = params.get('category') || 'all';
            const difficulty = params.get('difficulty') || 'all';

            const filtered = roomsData.filter(room => {
                const matchesCategory = category === 'all' || room.category === category;
                const matchesDifficulty = difficulty === 'all' || room.difficulty === difficulty;
                return matchesCategory && matchesDifficulty;
            });
            
            renderRooms(filtered, resultsRoomList, resultsRoomCount);

            dashboardView.classList.add('hidden');
            resultsView.classList.remove('hidden');
        } else {
            dashboardView.classList.remove('hidden');
            resultsView.classList.add('hidden');
        }
    };

    exploreBtn.addEventListener('click', () => {
        const selectedCategory = categorySelect.value;
        const selectedDifficulty = difficultySelect.value;
        window.location.hash = `#results?category=${selectedCategory}&difficulty=${selectedDifficulty}`;
    });

    backBtn.addEventListener('click', () => { window.location.hash = ''; });
    modalCloseBtn.addEventListener('click', closeModal);
    modalOverlay.addEventListener('click', closeModal);
    
    window.addEventListener('hashchange', handleViewChange);

    // Cursor effect logic
    document.addEventListener('mousemove', (e) => {
        document.body.style.setProperty('--x', `${e.clientX}px`);
        document.body.style.setProperty('--y', `${e.clientY}px`);
    });

    // Initial setup
    populateFilters();
    createCharts();
    renderRooms(roomsData, initialRoomList, initialRoomCount);
    handleViewChange();
});