# AI-Powered Red Teaming: Research Papers & Tools
## Comprehensive Collection (2023-2024)

A curated list of 35+ cutting-edge papers and tools on using AI/LLMs for offensive security, penetration testing, vulnerability discovery, and automated red teaming.

---

## 🤖 LLM Red Teaming & Jailbreaking

### 1. *Automatic LLM Red Teaming*
- arXiv, August 2025
- Hierarchical planning and task-specific agents (HPTSA)
- Multi-turn attacks, context-aware jailbreaking
- [Paper](https://arxiv.org/html/2508.04451v1)

### 2. *Recent Advancements in LLM Red-Teaming*
- arXiv, October 2024
- Comprehensive survey of techniques, defenses, ethical considerations
- Covers GBRT, ReNeLLM, GPTFuzz, WordGame, MASTERKEY
- [Paper](https://arxiv.org/html/2410.09097v1)

### 3. *The Automation Advantage in AI Red Teaming*
- arXiv, April 2025
- Based on Crucible platform (Black Hat 2024, GovTech Singapore 2024)
- 214,271 attack attempts across 30 LLM security challenges
- Analysis of automated vs manual red teaming effectiveness
- [Paper](https://arxiv.org/html/2504.19855v2)

### 4. *Prompt Injection Attack Against LLM-Integrated Applications*
- Referenced in multiple surveys, 2023
- 86.1% success rate for prompt injections
- Direct and indirect (cross-context) injection techniques

---

## 🕵 LLM Agents for Autonomous Hacking

### 5. *LLM Agents can Autonomously Exploit One-day Vulnerabilities* ⭐
- arXiv, April 2024 (Daniel Kang et al.)
- *GPT-4: 87% success rate* exploiting real-world CVEs
- All other models (GPT-3.5, open-source): 0% success
- 15 vulnerabilities including critical severity
- [Paper](https://arxiv.org/abs/2404.08144) | [Analysis](https://www.ionix.io/blog/autonomous-llm-exploit-one-day-vulnerabilities-arxiv-2404-08144-explained/)

### 6. *Teams of LLM Agents can Exploit Zero-Day Vulnerabilities*
- arXiv, June 2024
- HPTSA method: 50%+ success on zero-day vulnerabilities
- Previous single agents: 20% | Scanners: 0%
- Multi-agent system with planning, manager, task-specific experts
- [Paper](https://arxiv.org/html/2406.01637v1) | [Blog](https://medium.com/@danieldkang/llm-agents-can-autonomously-exploit-zero-day-vulnerabilities-e4664d7c598e)

### 7. *Multi-Agent Penetration Testing AI for the Web (MAPTA)*
- arXiv, August 2025
- 76.9% coverage on XBOW benchmark (commercial: 84.6%)
- Discovered 19 vulnerabilities (14 high/critical, 10 pending CVEs)
- Open-source, reproducible evaluation
- [Paper](https://arxiv.org/pdf/2508.20816)

### 8. *AutoPentest: Enhancing Vulnerability Management*
- arXiv, May 2025
- Autonomous LLM agent for HTB (Hack The Box) machines
- Evaluated on machines released after GPT-4o training cutoff
- RAG-based approach with specialized workers
- [Paper](https://arxiv.org/html/2505.10321v1)

### 9. *Critical Perspective: "No, LLM Agents Cannot..."*
- Blog analysis by Chris Rohlf, 2024
- Critical examination of autonomous hacking claims
- Argues GPT-4 excels at intelligent scanning, not exploit generation
- Important for understanding realistic capabilities
- [Analysis](https://secure.dev/auto_agents_1_day.html)

---

## 🛠 AI-Powered Penetration Testing Tools

### 10. *HackGPT Enterprise*
- Open-source AI pentesting suite (2025)
- Multi-model support: GPT-4, local LLMs
- 50+ tool integrations, 15,000+ lines of code
- Six-phase framework: OSINT, scanning, exploitation, reporting
- [GitHub](https://github.com/zehrasec/hackgpt) | [Article](https://gbhackers.com/hackgpt-launches-as-ai-driven-penetration-testing-suite/)

### 11. *PentestGPT*
- Available on GitHub
- AI assistant for penetration testing
- Interactive testing guidance

### 12. *State of Pentesting 2024 Report* (Cobalt)
- 75% of teams adopted new AI tools
- Top AI pentest vulnerabilities: prompt injection, model DoS, prompt leaking
- 57% say AI demand outpaced security team's ability
- [Report](https://www.cobalt.io/blog/state-of-pentesting-2024-impact-of-llms-on-penetration-testing)

---

## 🔬 LLM-Based Fuzzing & Testing

### 13. *Fuzz4All: Universal Fuzzing with LLMs*
- ICSE, 2024
- Uses GPT-4 and StarCoder for multi-language fuzzing
- Works across different programming languages
- Leverages LLM understanding of syntax and semantics

### 14. *Large Language Models are Zero-Shot Fuzzers*
- ISSTA, 2023
- LLMs for fuzzing deep-learning libraries
- No training data required for fuzzing
- [Referenced in surveys]

### 15. *Large Language Models Based Fuzzing Techniques: A Survey*
- arXiv, February 2024
- Comprehensive survey of LLM-based fuzzing
- Covers ChatAFL, ChemFuzz, InputBlaster, BertRLFuzzer
- [Paper](https://arxiv.org/html/2402.00350v1)

### 16. *Systematic Review of Fuzzing Based on ML Techniques*
- PLOS ONE, 2020 (highly cited)
- 44 papers reviewed on ML for fuzzing
- Covers seed generation, mutation, testcase filtering
- [Paper](https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0237749)

### 17. *Learn&Fuzz: Machine Learning for Input Fuzzing*
- ASE, 2017 (foundational work)
- Neural network-based grammar learning for fuzzing
- Applied to PDF parser in Microsoft Edge
- [Paper](https://ieeexplore.ieee.org/document/8115618/)

### 18. *Prompt Fuzzing for Fuzz Driver Generation*
- ACM CCS, 2024
- Uses LLMs to generate fuzz drivers
- Automated harness synthesis
- [Paper](https://dl.acm.org/doi/10.1145/3658644.3670396)

### 19. *FuzzingPaper - Comprehensive Paper List*
- Curated collection of 100+ fuzzing papers
- Includes ML-based fuzzing from top conferences
- Papers from IEEE S&P, USENIX Security, CCS, NDSS
- [GitHub Repo](https://wcventure.github.io/FuzzingPaper/)

---

## 💻 Code Vulnerability Detection with LLMs

### 20. *IRIS: LLM-Assisted Static Analysis* ⭐
- arXiv, May 2024 (Ziyang Li et al.)
- Combines GPT-4 with CodeQL for whole-repository analysis
- *55 vulnerabilities detected* vs CodeQL's 27 (on CWE-Bench-Java)
- 4 previously unknown vulnerabilities discovered
- [Paper](https://arxiv.org/abs/2405.17238) | [OpenReview](https://openreview.net/forum?id=9LdJDU7E91)

### 21. *LLMs in Software Security: Survey of Vulnerability Detection*
- ACM Computing Surveys, 2024
- Systematic analysis of LLM applications in vuln detection
- Reviews 60+ papers from 2017-2025
- Covers problem formulation, datasets, evaluation metrics
- [Paper](https://dl.acm.org/doi/10.1145/3769082)

### 22. *Vercation: LLM-Enhanced Static Analysis*
- arXiv, August 2024
- Identifies vulnerable OSS versions
- Combines static analysis, LLM, semantic code clone detection
- Focus on C/C++ open-source software
- [Paper](https://arxiv.org/html/2408.07321v1)

### 23. *An LLM-Assisted Easy-to-Trigger Backdoor Attack*
- USENIX Security, 2024
- Uses LLMs to evade static analysis tools
- CODEBREAKER attack methodology
- Tests against Semgrep, Bandit, Snyk, GPT-4
- [Paper](https://www.usenix.org/system/files/usenixsecurity24-yan.pdf)

### 24. *System for Automatic Bug Detection Using LLMs and AI Agents*
- SpringerLink, 2024
- Integrates Dante system with LLMs
- Reinforcement learning for vulnerability detection
- Multi-step automated workflow
- [Paper](https://link.springer.com/chapter/10.1007/978-3-032-03705-3_11)

### 25. *Awesome-LLM4Cybersecurity GitHub Repo*
- Comprehensive collection of papers on LLMs for cybersecurity
- 100+ papers organized by topic
- Includes vulnerability detection, malware analysis, threat intelligence
- [GitHub](https://github.com/tmylla/Awesome-LLM4Cybersecurity)

---

## 🎯 Practical AI Red Teaming Frameworks

### 26. *DeepTeam* (Confident AI)
- Open-source LLM red teaming framework
- OWASP Top 10 for LLMs, NIST AI RMF support
- Tests for bias, PII leakage, jailbreaking, prompt injection
- Dynamic attack simulation, no dataset required
- [GitHub](https://github.com/confident-ai/deepteam) | [Guide](https://www.confident-ai.com/blog/red-teaming-llms-a-step-by-step-guide)

### 27. *Microsoft PyRIT* (Python Risk Identification Toolkit)
- Open-source red teaming tool for GenAI systems
- Works with local and cloud models
- De-facto standard for orchestrating LLM attack suites

### 28. *Promptfoo*
- Simple setup for common test cases
- Popular for teams starting LLM red teaming

### 29. *Garak*
- Open-source LLM attack framework
- Similar to PyRIT functionality

---

## 📚 Industry Reports & Practical Guides

### 30. *Red Teaming LLM: Playbook for Secure GenAI Deployment*
- Ajith Vallath Prabhakar, July 2025
- Comprehensive guide on LLM red teaming
- Tool comparisons: PyRIT, DeepTeam, Promptfoo, Adversa, Repello
- Prompt fuzzing with LLMFuzzer
- [Article](https://ajithp.com/2025/07/13/red-teaming-large-language-models-playbook/)

### 31. *5 Ways to Use LLMs for Penetration Testing* (TechTarget)
- Practical guide for using ChatGPT, Gemini, Claude
- Analyzing HTTP traffic, state maintenance, JWT analysis
- Vulnerability identification, exploit development assistance
- [Article](https://www.techtarget.com/searchsecurity/tip/Red-teams-and-AI-Ways-to-use-LLMs-for-penetration-testing)

### 32. *AI and Cybersecurity in Penetration Testing* (EC-Council)
- Educational overview from certification body
- Discusses MIT AI2 system: 85% attack detection, 5x fewer false positives
- Ethical considerations and best practices
- [Article](https://www.eccouncil.org/cybersecurity-exchange/penetration-testing/ai-and-cybersecurity-in-penetration-testing/)

### 33. *Bugcrowd AI Penetration Testing Services*
- Commercial service launched 2024
- Human-led testing for LLM applications
- OWASP-based methodology
- Focus on prompt injection, model inversion, data poisoning
- [Service Page](https://www.bugcrowd.com/blog/introducing-ai-penetration-testing/)

---

## 🔍 Analysis & Commentary

### 34. *Penetration Testing in 2024* (SC Media)
- Industry overview of AI adoption in pentesting
- Cobalt Strike automation examples
- Cloud pentesting challenges
- Expert perspectives on future developments
- [Article](https://www.scworld.com/resource/penetration-testing-in-2024)

### 35. *Red Teaming in 2025: The Bleeding Edge* (CyCognito)
- Comprehensive overview of red teaming evolution
- LLM-specific red teaming applications
- Red vs Blue vs Purple team dynamics
- Best practices and CART (Continuous Automated Red Teaming)
- [Article](https://www.cycognito.com/learn/red-teaming/)

---

## 🎓 Key Researchers & Labs to Follow

*Daniel Kang* (UC Berkeley/UIUC)
- Pioneering work on LLM agents for hacking
- Papers on one-day and zero-day exploitation

*Richard Fang* (Stanford/Berkeley)
- Co-author on autonomous hacking papers
- Focus on real-world vulnerability exploitation

*Ziyang Li* (University of Illinois)
- IRIS system for LLM-assisted static analysis
- Combining neuro-symbolic approaches

*Microsoft Security Research*
- PyRIT framework development
- Counterfit for ML system attacks

*Anthropic & OpenAI*
- Red teaming of frontier models
- Safety research and jailbreaking defenses

*Dreadnode*
- Crucible CTF platform for AI red teaming
- Black Hat and GovTech competitions

---

## 📊 Key Datasets & Benchmarks

### Vulnerability Datasets:
- *CWE-Bench-Java*: 120 manually validated vulnerabilities (IRIS paper)
- *XBOW Benchmark*: 104 web vulnerability challenges for AI agents
- *Hack The Box (HTB)*: Real-world pentesting machines
- *VulnHub*: Vulnerable VMs for testing

### LLM Security:
- *Crucible*: 30 LLM security challenges
- *OWASP Top 10 for LLMs*: Standard vulnerability list

---

## 🛡 Defense & Mitigation

Papers focusing on defending against AI-powered attacks:

- *Adversarial Training* for robust models
- *Stateful Defenses* (often bypassed - see CCS 2023 papers)
- *LLM Guardrails* (Llama Guard, content filtering)
- *Detection Systems* for adversarial examples

---

## 🚀 Quick Start Guide for Researchers

### For Beginners:
1. Start with *DeepTeam* or *Promptfoo* for hands-on LLM red teaming
2. Read the *Playbook* (#30) for comprehensive overview
3. Experiment with prompt injection on safe test LLMs

### For Intermediate:
1. Implement *LLM agents* for simple hacking tasks (SQLi, XSS)
2. Try *IRIS* (#20) for code vulnerability detection
3. Use *PyRIT* for more advanced attack orchestration

### For Advanced:
1. Replicate *one-day vulnerability exploitation* (#5) study
2. Develop multi-agent systems for *zero-day discovery* (#6)
3. Contribute to *Crucible* benchmark challenges

---

## 💡 Research Gaps & Future Directions

1. *Cross-domain generalization*: Most work focuses on web vulnerabilities
2. *Cost-effectiveness*: GPT-4 API costs vs benefits
3. *Ethical frameworks*: Need for better responsible disclosure
4. *Defense mechanisms*: Defenses lag behind attacks
5. *Long-context reasoning*: Improving whole-repository analysis
6. *Multi-modal attacks*: Combining code, docs, infrastructure
7. *Autonomous vs assisted*: Finding the right balance

---

## ⚖ Ethical Considerations

*All research and tools should be used:*
- With proper authorization
- In sandboxed environments
- Following responsible disclosure
- Within legal boundaries
- For defensive purposes

*Red flags to avoid:*
- Unauthorized testing on production systems
- Sharing exploits publicly before patches
- Using AI for malicious purposes
- Violating terms of service

---

## 📈 Trend Analysis (2023-2025)

*Major shifts:*
- 2023: Initial LLM-assisted pentesting tools emerge
- 2024: Autonomous agents show real capabilities (87% one-day, 50% zero-day)
- 2025: Focus shifts to multi-agent systems, defenses, responsible deployment

*Hot topics now:*
- LLM jailbreaking and prompt injection
- Autonomous exploit generation
- Whole-repository vulnerability analysis
- AI red teaming platforms and competitions

---

## 🔗 Essential Tools Summary

| Tool | Type | Language | Use Case |
|------|------|----------|----------|
| *DeepTeam* | Framework | Python | LLM red teaming |
| *PyRIT* | Framework | Python | GenAI security testing |
| *HackGPT* | Platform | Multiple | Full pentesting suite |
| *IRIS* | Static Analysis | Java | Vulnerability detection |
| *Promptfoo* | Testing | JavaScript | Prompt security |
| *Garak* | Framework | Python | LLM attacks |
| *Crucible* | Platform | Web | AI CTF challenges |
| *PentestGPT* | Assistant | Python | Interactive pentesting |

---

Last Updated: December 2024
Focus: 2023-2024 papers, with emphasis on LLMs and AI agents
All tools and papers are for educational and defensive security purposes
