"""
Principle definitions for Basin principle detection prompts.

Sources:
  - Base definitions: Basin et al., "Security Principles" textbook, Chapter 1.3
  - Discriminating rules: derived from descriptive-normative gap logic
    (same methodology as S&S/CyBOK prompt definitions)
  - Few-shot examples: drawn from synthetic Security Stack Exchange dataset
    (1,800 responses across 12 principles, 5 personas, 3 response types)

Note on interpretation:
  Basin's 12 principles overlap with but are distinct from Saltzer &
  Schroeder's 8 principles. Where names overlap (e.g., Complete Mediation,
  Least Privilege), the Basin textbook framing is used, which is sometimes
  broader or differently emphasised than the S&S/CyBOK interpretation.

  Basin's "Simplicity" maps roughly to S&S "Economy of Mechanism" but is
  framed more broadly. Basin's "Compartmentalisation" overlaps with both
  S&S "Separation of Privilege" and "Least Common Mechanism". Basin adds
  principles not in S&S: Minimum Exposure, Minimum Trust & Maximum
  Trustworthiness, No Single Point of Failure, Traceability, and
  Generating Secrets.

Example labelling convention:
  - PRESENT examples: drawn from 'explicit' synthetic responses where the
    principle is named or directly argued for
  - ABSENT examples: drawn from 'unrelated' synthetic responses where the
    principle is not the target
  - BOUNDARY examples: drawn from 'implicit' synthetic responses where the
    principle is applied without being named — these test whether the
    detector can identify principle reasoning without surface keywords
"""

PRINCIPLE_DEFINITIONS = {

    "Simplicity": {
        "definition": """
Simplicity holds that security mechanisms should be kept as simple as
possible. This principle applies to any engineering and implementation task
involved in designing or maintaining a system. Simpler systems are less
likely to contain flaws, are easier to analyse and review, and it is thus
easier to establish their trustworthiness.

Basin connects this directly to Saltzer and Schroeder's Economy of Mechanism:
when protection mechanisms are inspected at the software and hardware levels,
a small and simple design is essential for such inspections to succeed. The
principle applies to all aspects of system design and development, for
operation and maintenance as well as for security mechanisms.
""",
        "discriminating_rule": """
The text must argue that simplicity or reduced complexity in security design
CAUSES better security outcomes — fewer flaws, easier verification, reduced
attack surface, or more manageable security posture. It is not enough to
describe that something is simple or complex; the text must connect the
design characteristic to a security consequence.

Ask: does this text make a normative claim that keeping security mechanisms
or architecture simple IS the reason security is improved? If yes, label
PRESENT. If the text merely describes a straightforward approach without
arguing that simplicity itself is the security benefit, label ABSENT.

IMPORTANT DISTINCTION: Simplicity is about the design of security mechanisms
and system architecture. If the text argues that security should be easy for
users to understand or use, that is Usability, not Simplicity. Simplicity
concerns the internal complexity of the mechanism, not the user experience.
""",
        "present_examples": [
            {
                "id": "SYNTH-Simplicity-explicit-RedTeamer-Q1",
                "text": "Keep it simple: don't give standard users admin privileges. Even with UAC, you're adding complexity and increasing attack surface. Stick to separate admin accounts for necessary tasks. This minimizes risk and keeps your security posture straightforward and manageable.",
                "reason": "Directly argues that adding complexity increases attack surface and that a straightforward approach minimises risk — simplicity as the explicit security rationale."
            },
            {
                "id": "SYNTH-Simplicity-explicit-RedTeamer-Q7",
                "text": "Keep it simple: don't trust the client, and handle everything critical server-side. By centralizing validation and logic on the server, you reduce complexity and potential attack vectors. This approach not only simplifies your security model but also makes it easier to audit and test.",
                "reason": "Argues that centralising logic reduces complexity and attack vectors, and that the simplified model is easier to audit — connecting simplicity to verifiability and security."
            },
        ],
        "absent_examples": [
            {
                "id": "SYNTH-Simplicity-unrelated-SAT-Q7",
                "text": "When discussing client interactions, it's crucial to focus on user education and awareness. Training users to recognize potential threats and understand the importance of secure practices can significantly reduce risks. Regular workshops and clear communication about security policies can empower users to make safer choices.",
                "reason": "Focuses on user training and awareness. Makes no claim about keeping security mechanisms simple or that reduced complexity improves security."
            },
            {
                "id": "SYNTH-Simplicity-unrelated-SAT-Q4",
                "text": "Focus on making the transition as smooth and user-friendly as possible. Offer hands-on training sessions where users can ask questions and get comfortable with the new system. Highlight the benefits they care about, like faster access to files and improved communication tools.",
                "reason": "Discusses smooth user transitions and user-friendliness — this is a usability concern, not an argument that the security mechanism itself should be simple."
            },
        ],
        "boundary_examples": [
            {
                "id": "SYNTH-Simplicity-implicit-SAT-Q7",
                "text": "Focus on keeping your security measures straightforward. Always handle validation and authentication on the server side to maintain control. This approach reduces complexity and minimizes potential errors. By doing so, you ensure that your defenses are robust and easier to manage.",
                "label": "PRESENT",
                "reason": "Does not name the Simplicity principle but argues that keeping measures straightforward reduces complexity and minimises errors — the core normative claim. This is an implicit application: the reasoning matches the principle even though the keyword is absent."
            },
            {
                "id": "SYNTH-Simplicity-implicit-IR-Q1",
                "text": "Keep it straightforward: separate standard and admin accounts. This minimizes risk and keeps things clear-cut. UAC prompts are helpful, but they aren't foolproof. By maintaining distinct accounts, you reduce the attack surface and make it easier to manage incidents when they occur.",
                "label": "PRESENT",
                "reason": "Uses 'straightforward' and 'clear-cut' rather than naming the principle, but the security argument is that a simpler account structure reduces attack surface and eases incident management — Simplicity reasoning without the label."
            },
        ],
    },

    "Open Design": {
        "definition": """
Open Design holds that the security of a system should not depend on the
secrecy of its protection mechanisms. The mechanisms should not depend on the
ignorance of potential adversaries, but rather on the possession of specific,
more easily protected, keys or passwords.

Basin connects this to Kerckhoffs' principle in cryptography: a cryptosystem
should be secure even if all aspects of the system (except the keys being
used) are public knowledge. Secrets are hard to protect and must be stored
and managed carefully. The amount of information that needs to be kept secret
should therefore be reduced to a minimum. We do not design doors that only
authorised persons know how to open; instead, we design standardised doors
with standardised locks and rely on the protection of the key.
""",
        "discriminating_rule": """
The text must argue that security should NOT rely on secrecy of design or
mechanisms, OR that transparency and openness of design ENABLES better
security through review, scrutiny, or reduced dependence on obscurity. The
text should connect openness to a security benefit (peer review, reduced
secret surface, resilience to reverse engineering).

It is NOT enough to describe that a system is transparent, that communication
is open, or that users are informed about security measures. The text must
make a normative claim: that depending on secrecy of mechanisms IS a
vulnerability, or that open design IS a security strategy.

IMPORTANT DISTINCTION: If the text argues for transparency in communication
with users about security changes, that is closer to Usability or change
management — not Open Design. Open Design specifically concerns whether the
SECURITY MECHANISM ITSELF relies on secrecy for its effectiveness.
""",
        "present_examples": [
            {
                "id": "SYNTH-OpenDesign-explicit-RedTeamer-Q9",
                "text": "Security isn't about hiding the design; it's about making sure the design is robust even when fully exposed. Open design means that the security of a system doesn't rely on keeping its mechanisms secret, but rather on the strength of its algorithms and protocols. In red teaming, we exploit weaknesses in systems that rely on secrecy rather than robust design.",
                "reason": "Directly argues that security should not rely on hiding mechanism design and that open, robust design is the correct approach — the core Open Design claim with explicit contrast to security-through-obscurity."
            },
        ],
        "absent_examples": [
            {
                "id": "SYNTH-OpenDesign-unrelated-CISO-Q4",
                "text": "Focus on the tangible benefits that users can immediately appreciate, like improved system performance and access to new tools such as the updated MS Office. Highlight how these changes make their daily tasks easier and more efficient. Encourage open communication by being approachable and responsive to their concerns.",
                "reason": "Mentions 'open communication' but in the context of user relations and change management, not in the context of whether security mechanisms should be open to scrutiny. No claim about mechanism design or Kerckhoffs' principle."
            },
            {
                "id": "SYNTH-OpenDesign-unrelated-RedTeamer-Q10",
                "text": "If you're looking to streamline operations, consider the potential attack vectors. A single security group might simplify management, but it also creates a larger target for exploitation. As a red teamer, I'd be more interested in how quickly I could pivot from one compromised account to another.",
                "reason": "Discusses attack vectors and security group management. No claim about whether security should depend on design secrecy or openness."
            },
        ],
        "boundary_examples": [
            {
                "id": "SYNTH-OpenDesign-implicit-IR-Q4",
                "text": "Transparency is key here. Share with your users how the new system works and why it's beneficial. By explaining the security measures and how they protect both the company and individual users, you can demystify the process and build trust. Encourage open dialogue and feedback, so they feel involved and understand that these changes are for their benefit.",
                "label": "PRESENT",
                "reason": "Uses transparency language and argues for sharing how the system works with users. Although framed as a communication strategy, the underlying argument is that exposing how security measures work builds trust and effectiveness — an implicit Open Design argument that the mechanism should withstand scrutiny."
            },
            {
                "id": "SYNTH-OpenDesign-implicit-RedTeamer-Q4",
                "text": "Show them the blueprint of your security setup. When users understand how the system is designed to protect them and the company, they're more likely to appreciate the changes. Transparency about how security measures work can demystify the process and reduce resistance.",
                "label": "PRESENT",
                "reason": "Advocates showing 'the blueprint' of security, arguing that understanding the design improves acceptance. Implicitly argues that the mechanism can and should withstand exposure — Open Design reasoning without naming the principle."
            },
        ],
    },

    "Compartmentalisation": {
        "definition": """
Compartmentalisation means organising resources into isolated groups of
similar needs. Each compartment is isolated from the others, except perhaps
for some limited and controlled means of exchanging information.

Basin emphasises several applications: sensitive applications on separate
computers to limit breach impact; firewalls partitioning networks into zones;
software compartmentalization through encapsulation and modularisation; and
separation of data and code to prevent injection attacks. A key benefit is
that problems resulting from attacks or operational mishaps are often isolated
to a single compartment, reducing the negative effects and providing
mechanisms for tackling the problem.

While compartmentalization implies separation, it is often infeasible to
completely isolate resources, so interfaces between compartments must be
tightly controlled to prevent them becoming sources of vulnerability.
""",
        "discriminating_rule": """
The text must argue that isolating or separating resources, components, or
domains into compartments LIMITS the impact of compromise, PREVENTS lateral
movement, or CONTAINS damage to a single area. The text should connect
structural isolation to a security benefit.

It is NOT enough to describe that systems are separated, that different
teams have different access, or that a network has zones. The text must make
a normative claim: that compartmentalization IS the security strategy, or
that failure to compartmentalize IS the vulnerability.

IMPORTANT DISTINCTION FROM RELATED PRINCIPLES: Compartmentalisation is about
architectural isolation of resources into groups. If the text argues for
limiting what a single subject can do, that is Least Privilege. If it argues
for minimising shared mechanisms between parties, that is closer to Minimum
Exposure. Compartmentalisation specifically concerns organising resources
into isolated groups to contain compromise.
""",
        "present_examples": [
            {
                "id": "SYNTH-Compartment-explicit-RedTeamer-Q9",
                "text": "Encryption isn't about obscurity; it's about compartmentalization. By keeping keys and sensitive data separate and isolated, we limit the impact of a breach. Even if one part is compromised, the rest remains secure. This is a fundamental strategy in red teaming: break down the system into compartments, and you'll see how each part is protected not by obscurity, but by strategic isolation and control.",
                "reason": "Directly names compartmentalization and argues that separating and isolating data limits breach impact — the core normative claim that isolation contains compromise."
            },
            {
                "id": "SYNTH-Compartment-explicit-RedTeamer-Q10",
                "text": "Create two separate security groups for TeamAlice and TeamBob to maintain compartmentalisation. This approach ensures that each team only has access to the resources they need, minimizing the risk of lateral movement if one group is compromised.",
                "reason": "Explicitly recommends compartmentalization to prevent lateral movement between compromised groups — connecting isolation to damage containment."
            },
        ],
        "absent_examples": [
            {
                "id": "SYNTH-Compartment-unrelated-RedTeamer-Q8",
                "text": "If you're worried about unauthorized access, consider setting up honeypots or decoy accounts to see if the admin takes the bait. You could also monitor for unusual patterns in network traffic or use behavioral analytics to spot anomalies. Remember, it's all about thinking like an attacker and staying one step ahead.",
                "reason": "Discusses detection techniques (honeypots, monitoring, analytics). No claim about isolating resources into compartments or that such isolation provides a security benefit."
            },
            {
                "id": "SYNTH-Compartment-unrelated-CISO-Q4",
                "text": "Focus on the tangible benefits that users can immediately appreciate, like improved system performance and access to new tools such as the updated MS Office. Highlight how these changes make their daily tasks easier and more efficient. Encourage open communication by being approachable and responsive to their concerns.",
                "reason": "Discusses user-facing benefits and communication. No structural isolation argument or compartmentalization claim."
            },
        ],
        "boundary_examples": [
            {
                "id": "SYNTH-Compartment-implicit-SAT-Q9",
                "text": "Security isn't just about hiding secrets; it's about structuring your defenses so that if one part is compromised, the rest remains secure. Think of it like having multiple layers and sections in a building, each with its own lock and key. Even if someone gets through one door, they can't access everything.",
                "label": "PRESENT",
                "reason": "Does not name compartmentalization but describes the exact principle: structuring defences into sections so that compromise of one part does not affect the rest. The building analogy directly expresses the isolation rationale."
            },
            {
                "id": "SYNTH-Compartment-implicit-RedTeamer-Q10",
                "text": "Create separate security groups for each team and their respective computers. This setup minimizes the risk of unauthorized access and limits the potential impact of a breach. By isolating permissions, you ensure that any compromise in one group doesn't automatically extend to the other.",
                "label": "PRESENT",
                "reason": "Recommends isolating permissions into separate groups to limit breach impact without naming the principle — implicit compartmentalization reasoning."
            },
        ],
    },

    "Minimum Exposure": {
        "definition": """
Minimum Exposure holds that the attack surface a system presents to an
adversary should be minimised. This principle mandates minimising the
possibilities for a potential adversary to attack a system. It advocates:
(1) reducing external interfaces to a minimum, (2) limiting the amount of
information given away, and (3) minimising the window of opportunity for
an adversary by limiting the time available for attack.

Basin gives practical examples: disabling unnecessary functionality and
services (especially externally available ones like infrared, WLAN, Bluetooth);
limiting information leakage from poorly configured servers that reveal
software versions; and using automatic session timeouts and account lockouts
to reduce the adversary's window of opportunity.
""",
        "discriminating_rule": """
The text must argue that reducing the attack surface, limiting exposed
interfaces, restricting disclosed information, or narrowing the window of
opportunity PREVENTS or reduces the likelihood of attack. The text should
connect exposure reduction to a security benefit.

It is NOT enough to describe what interfaces or information a system has,
or that access controls exist. The text must make a normative claim: that
minimising exposure IS the security strategy, or that excessive exposure
IS the vulnerability.

IMPORTANT DISTINCTION FROM RELATED PRINCIPLES: If the text argues for
limiting what a subject is permitted to do, that is Least Privilege. If it
argues for isolating resources into separate groups, that is Compartmentalisation.
Minimum Exposure specifically concerns reducing what the adversary can SEE,
REACH, or INTERACT WITH from outside the system boundary.
""",
        "present_examples": [
            {
                "id": "SYNTH-MinExposure-explicit-CISO-Q8",
                "text": "To ensure minimum exposure, it's crucial to limit admin access to only what's necessary for their role. Implement role-based access controls and audit logs to monitor who accesses sensitive emails. Use tools that provide detailed logging and alerting for unauthorized access attempts. Regularly review and adjust permissions to ensure they align with the principle of least privilege.",
                "reason": "Explicitly names minimum exposure and argues for limiting access and monitoring to reduce what adversaries can reach — connecting reduced exposure to security."
            },
        ],
        "absent_examples": [
            {
                "id": "SYNTH-MinExposure-unrelated-RedTeamer-Q8",
                "text": "If you're worried about unauthorized access, consider setting up a honeypot email account with enticing subject lines to see if anyone takes the bait. You could also use a script to monitor access logs for unusual patterns or times of access. Remember, it's all about thinking like an attacker to anticipate their moves.",
                "reason": "Discusses detection (honeypots, log monitoring) rather than reducing what is exposed. No claim about minimising the attack surface or limiting information disclosure."
            },
            {
                "id": "SYNTH-MinExposure-unrelated-RedTeamer-Q1",
                "text": "If you're looking to keep things efficient, consider the operational overhead of managing multiple accounts. It can be a hassle for users to switch between accounts, and it might slow down their workflow. Instead, focus on monitoring and logging activities to catch any suspicious behavior quickly.",
                "reason": "Focuses on operational efficiency and monitoring. No argument about reducing what is exposed to adversaries."
            },
        ],
        "boundary_examples": [
            {
                "id": "SYNTH-MinExposure-implicit-RedTeamer-Q7",
                "text": "Absolutely, never trust the client. But beyond that, limit what the client can see and interact with. Expose only the necessary endpoints and data, and keep everything else locked down. This reduces the attack surface and makes it harder for an attacker to find a way in.",
                "label": "PRESENT",
                "reason": "Does not name Minimum Exposure but argues for limiting exposed endpoints and data to reduce attack surface — the core principle reasoning expressed as a practical recommendation."
            },
            {
                "id": "SYNTH-MinExposure-implicit-RedTeamer-Q8",
                "text": "Limit admin access to only what's necessary for their role. Implement strict logging and monitoring on email access, focusing on high-value targets like the CEO's account. Use role-based access controls to ensure only authorized personnel can access sensitive emails, and regularly audit these logs to detect any unauthorized access.",
                "label": "PRESENT",
                "reason": "Argues for limiting access and focusing controls on high-value targets without naming the principle — implicitly reducing exposure through access restriction."
            },
        ],
    },

    "Least Privilege": {
        "definition": """
Least Privilege holds that any component (and user) of a system should
operate using the least set of privileges necessary to complete its job.
Privileges should be reduced to the absolute minimum, and as a consequence,
subjects should not be allowed to access objects other than those really
needed to complete their jobs.

Basin emphasises that this principle helps to minimise the negative
consequences of unexpected operation errors and reduces the negative effects
of deliberate attacks carried out by subjects with privileges. Ensuring it
requires understanding the system design and architecture as well as the
tasks that should be carried out by system users. Implementation is often
difficult because fine-grained and well-defined security policies rarely
exist, and necessary access must be identified on a case-by-case basis.
""",
        "discriminating_rule": """
The text must argue that restricting the operations, access rights, or
privileges of a subject to the minimum necessary REDUCES the security impact
of compromise, error, or misuse. The text should connect privilege limitation
to a security rationale.

It is NOT enough to describe what access rights exist or how permissions are
structured. The text must make a normative claim: that minimum-privilege
operation IS the security goal, or that excessive privilege IS the
vulnerability.

IMPORTANT DISTINCTION: If the text argues for isolating groups of resources
from each other, that is Compartmentalisation. If it argues for reducing
the externally visible attack surface, that is Minimum Exposure. Least
Privilege specifically concerns what an individual subject (user, process,
component) is PERMITTED to do.
""",
        "present_examples": [
            {
                "id": "SYNTH-LP-explicit-IR-Q7",
                "text": "As an Incident Responder, it's crucial to apply the principle of least privilege alongside not trusting the client. Ensure that users and applications have only the minimum access necessary to perform their functions. This limits the potential damage from malicious input or compromised accounts. By enforcing least privilege, even if a client-side validation is bypassed, the impact is contained.",
                "reason": "Explicitly names least privilege and argues that minimum access limits damage from compromise — the core normative claim connecting privilege restriction to damage containment."
            },
            {
                "id": "SYNTH-LP-explicit-RedTeamer-Q1",
                "text": "Giving standard users administrative privileges violates the principle of least privilege, which is crucial for minimizing attack surfaces. Even with UAC, if a user's account is compromised, an attacker could potentially escalate privileges more easily. Instead, use separate admin accounts for tasks that require elevated access.",
                "reason": "Names the principle violation and argues that excessive privilege enables easier escalation — connecting privilege excess to increased risk."
            },
        ],
        "absent_examples": [
            {
                "id": "SYNTH-LP-unrelated-RedTeamer-Q7",
                "text": "When you're dealing with client-side interactions, think like an attacker. Look for ways to exploit the client-server communication, such as intercepting and modifying requests. Focus on identifying weak spots in the application's logic that can be manipulated.",
                "reason": "Discusses attack techniques and exploitation. No claim about restricting privileges or that minimum access reduces risk."
            },
            {
                "id": "SYNTH-LP-unrelated-IR-Q4",
                "text": "Focus on the practical benefits that users can immediately appreciate. Highlight how the new system improves their daily workflow, like faster access to files and better communication tools. Emphasize the convenience of having IT support readily available to resolve any issues they encounter.",
                "reason": "Discusses user-facing benefits of a system change. No argument about privilege restriction or minimum access."
            },
        ],
        "boundary_examples": [
            {
                "id": "SYNTH-LP-implicit-RedTeamer-Q1",
                "text": "Giving users elevated access on their primary accounts is like handing them the keys to the kingdom. Instead, keep their day-to-day accounts limited and use separate credentials for admin tasks. This way, if their main account gets compromised, the attacker doesn't get a free pass to wreak havoc.",
                "label": "PRESENT",
                "reason": "Does not name Least Privilege but argues for keeping day-to-day accounts limited so that compromise does not grant broad access — implicit least privilege reasoning through the 'keys to the kingdom' metaphor."
            },
            {
                "id": "SYNTH-LP-implicit-RedTeamer-Q9",
                "text": "Encryption isn't about obscurity; it's about ensuring that only those who need access to the secret keys have them. The strength lies in the fact that even if someone knows the algorithm, they can't break it without the keys. By limiting access to these keys, you minimize the risk of exposure.",
                "label": "PRESENT",
                "reason": "Argues for limiting key access to only those who need it, minimising exposure risk — applies least privilege reasoning to cryptographic key management without naming the principle."
            },
        ],
    },

    "Minimum Trust and Maximum Trustworthiness": {
        "definition": """
Minimum Trust and Maximum Trustworthiness holds that trust placed in a system
should be minimised, and the trustworthiness of the system should be
maximised. A user who trusts a system assumes it will satisfy their
expectations, but this is just an assumption — a trusted system may
'misbehave', including acting maliciously. In contrast, a trustworthy system
actually satisfies the user's expectations.

Basin emphasises: minimise expectations and thus trust placed in systems,
especially when integrating third-party sub-systems. Maximise trustworthiness
by turning assumptions into validated properties — one way is to rigorously
prove that external systems behave only in expected (secure) ways. Trust
should be avoided whenever possible; systems relying on external input
should verify that input is actually valid rather than trusting that only
valid inputs will be provided.
""",
        "discriminating_rule": """
The text must argue that minimising trust in components, inputs, or external
systems IMPROVES security, OR that maximising the verifiability or
trustworthiness of a system REDUCES risk. The text should connect trust
reduction or trustworthiness enhancement to a security outcome.

It is NOT enough to describe that a system validates input or that
authentication exists. The text must make a normative claim: that trusting
without verification IS the vulnerability, or that verification and
validation ARE the security strategy because trust alone is insufficient.

IMPORTANT DISTINCTION: If the text argues for checking every access request,
that is Complete Mediation. If it argues for validating input to prevent
exploitation, that may be Minimum Trust — but only if it frames the argument
as 'do not trust the input source' rather than 'check access consistently'.
The key is whether the text frames the problem as one of TRUST.
""",
        "present_examples": [
            {
                "id": "SYNTH-MinTrust-explicit-RedTeamer-Q8",
                "text": "To ensure minimum trust and maximum trustworthiness, implement strict access controls and logging on the mail server. Use role-based access to limit admin privileges and deploy audit logs to track who accesses specific mailboxes. Regularly review these logs and employ anomaly detection to flag unauthorized access. This approach minimizes the need to trust admins blindly and maximizes the system's ability to verify their actions.",
                "reason": "Explicitly names the principle and argues that controls and logging replace blind trust in administrators with verifiable oversight — the core normative claim."
            },
        ],
        "absent_examples": [
            {
                "id": "SYNTH-MinTrust-unrelated-IR-Q8",
                "text": "To detect if a system admin is accessing the CEO's emails, you can implement logging and monitoring on the email server. Look for unusual access patterns or timestamps that don't align with the admin's regular duties. Additionally, consider using email auditing tools that can track who accesses specific mailboxes.",
                "reason": "Describes monitoring and detection techniques. Does not frame the problem as one of trust — no argument that trust should be minimised or that verification replaces trust."
            },
            {
                "id": "SYNTH-MinTrust-unrelated-IR-Q4",
                "text": "Focus on the practical benefits that users can directly experience. Highlight how the new system will streamline their daily tasks, reduce downtime, and improve overall efficiency. Emphasize the convenience of having centralized support and faster troubleshooting when issues arise.",
                "reason": "Discusses operational benefits and user experience. No claim about trust relationships or the need to verify rather than trust."
            },
        ],
        "boundary_examples": [
            {
                "id": "SYNTH-MinTrust-implicit-RedTeamer-Q7",
                "text": "Absolutely, never trust the client. Assume every interaction is potentially hostile. Validate and sanitize everything server-side, and ensure your server logic is robust against manipulation. Always verify authentication and authorization independently of client input. Remember, the client can be compromised, so your server must be the ultimate gatekeeper.",
                "label": "PRESENT",
                "reason": "Does not name the principle but directly expresses its core: 'never trust the client' because it can be compromised, and verify everything independently. This is Minimum Trust reasoning applied to client-server architecture."
            },
            {
                "id": "SYNTH-MinTrust-implicit-RedTeamer-Q9",
                "text": "Encryption isn't about obscurity; it's about building systems that don't require trust in secrecy alone. The strength lies in the math, not in hiding the keys. As a Red Teamer, I exploit systems that rely on obscurity because once the secret is out, the system fails. A robust system should not require trust in any single component.",
                "label": "PRESENT",
                "reason": "Argues that systems should not require trust in secrecy and that relying on trust is exploitable — Minimum Trust reasoning applied to cryptographic design, without naming the principle."
            },
        ],
    },

    "Secure Fail-Safe Defaults": {
        "definition": """
Secure Fail-Safe Defaults holds that a system should start in and return to
a secure state in the event of a failure. Security mechanisms should be
designed so that the system starts in a secure state and is re-enabled
whenever the system or a subsystem fails.

Basin emphasises the role in access control: the default and fail-safe state
should prevent any access. The access control system should identify
conditions under which access is granted; if conditions are not identified,
access should be denied (the default). This is the whitelist approach:
permission is denied unless explicitly granted. The opposite (less secure)
variant is the blacklist approach: permission is granted unless explicitly
denied. A design mistake in a whitelist system tends to fail by refusing
permission (safe, quickly detected), whereas a blacklist mistake tends to
fail by allowing access (unsafe, may go unnoticed).
""",
        "discriminating_rule": """
The text must argue that defaulting to a secure or restrictive state on
failure, error, or uncertainty PREVENTS exploitation or maintains security,
OR that systems should use inclusion-based (whitelist) rather than
exclusion-based (blacklist) approaches. The text should connect fail-safe
behaviour to a security benefit.

It is NOT enough to describe that a system has error handling, enters an
error state, or has access controls. The text must make a normative claim:
that defaulting to denial or a secure state IS the correct security
strategy, or that defaulting to permissive behaviour IS the vulnerability.

IMPORTANT DISTINCTION: If the text argues for checking every access (not
just on failure), that is Complete Mediation. If it argues for limiting
privileges, that is Least Privilege. Secure Fail-Safe Defaults specifically
concerns what happens WHEN SOMETHING GOES WRONG — the system's default
posture in the face of failure, ambiguity, or unexpected input.
""",
        "present_examples": [
            {
                "id": "SYNTH-FSD-explicit-RedTeamer-Q1",
                "text": "No, your colleague's approach isn't secure. Secure fail-safe defaults mean that when something goes wrong, the system should default to a secure state. By giving standard accounts administrative privileges, you're increasing the attack surface and relying on UAC as a safeguard, which isn't foolproof. Stick to separate admin accounts; if something fails, the default should be no access, not elevated privileges.",
                "reason": "Explicitly names the principle and argues that the default on failure should be no access rather than elevated privileges — directly connecting fail-safe design to security."
            },
        ],
        "absent_examples": [
            {
                "id": "SYNTH-FSD-unrelated-RedTeamer-Q8",
                "text": "If you're looking to catch a sysadmin snooping around, think like an attacker. Consider setting up honey tokens or decoy emails that would be irresistible to someone with unauthorized access. Monitor access logs for unusual patterns or times of access that don't align with the admin's regular duties.",
                "reason": "Discusses detection and monitoring techniques. No claim about what should happen on failure or that systems should default to a secure state."
            },
            {
                "id": "SYNTH-FSD-unrelated-SAT-Q1",
                "text": "It's crucial to consider the human factor in security. Training users to recognize when they're making changes and understanding the implications is key. While UAC prompts can serve as a reminder, they shouldn't be the sole line of defense. Regular security awareness training can empower users to make informed decisions.",
                "reason": "Focuses on user awareness and training. No argument about default system behaviour on failure."
            },
        ],
        "boundary_examples": [
            {
                "id": "SYNTH-FSD-implicit-RedTeamer-Q6",
                "text": "Use a cryptographically secure method like Node's `crypto.randomBytes` to generate the token, ensuring it's unpredictable. Hash it with a strong algorithm like bcrypt before storing it. Avoid including sensitive information directly in the token; instead, keep it simple and validate it server-side. If the token is invalid or expired, default to denying access without revealing specifics.",
                "label": "PRESENT",
                "reason": "The final sentence — 'default to denying access' on invalid or expired tokens — directly expresses fail-safe default behaviour without naming the principle. The security recommendation is that the default on failure should be denial."
            },
            {
                "id": "SYNTH-FSD-implicit-RedTeamer-Q7",
                "text": "When you're on the offensive side, you know that any client-side validation is just a speed bump. Always assume the worst-case scenario: if something can go wrong, it will. Design your systems so that if a client fails to provide valid input, the default action is to deny access or drop the request.",
                "label": "PRESENT",
                "reason": "Argues for designing systems to deny access when input is invalid — fail-safe default reasoning framed as defensive design. Does not name the principle but expresses its core: default to denial on unexpected input."
            },
        ],
    },

    "Complete Mediation": {
        "definition": """
Complete Mediation holds that access to any object must be monitored and
controlled. Every access to every security-relevant object within a system
must be checked. The access control mechanism must encompass all relevant
objects and must be operational in any state the system can possibly enter,
including normal operation, shutdown, maintenance mode, and failure.

Basin warns that care should be taken to ensure the access control mechanism
cannot be circumvented. Sensitive information should be protected during
transit and in storage. A system that merely controls access to unencrypted
objects can often be attacked by means of layer-below attacks. Saltzer and
Schroeder additionally mention identification as a prerequisite and warn
against caching authorisation information — if authority changes, cached
results must be systematically updated.
""",
        "discriminating_rule": """
The text must argue that checking, monitoring, or controlling every access
request consistently and without exception IS necessary for security, OR that
failure to mediate every access CREATES a vulnerability. The text should
connect the completeness of access checking to a security outcome.

It is NOT enough to describe that access controls or logging exist. The text
must make a normative claim: that every access MUST be checked, that gaps in
mediation ARE exploitable, or that consistent enforcement IS the security
requirement.

IMPORTANT DISTINCTION: If the text argues for defaulting to denial on
failure, that is Secure Fail-Safe Defaults. If the text argues for not
trusting inputs, that is Minimum Trust. Complete Mediation specifically
concerns the COMPLETENESS and CONSISTENCY of access checking across all
requests, all objects, and all system states.
""",
        "present_examples": [
            {
                "id": "SYNTH-CM-explicit-CO-Q8",
                "text": "To ensure compliance and apply the principle of Complete Mediation, every access request to the CEO's emails should be checked and logged. Implementing a robust auditing system that monitors and records all access attempts, including those by system admins, is crucial. This ensures that every action is mediated and can be reviewed for unauthorized access.",
                "reason": "Explicitly names Complete Mediation and argues that every access request should be checked and logged — the core normative claim about completeness of access control."
            },
        ],
        "absent_examples": [
            {
                "id": "SYNTH-CM-unrelated-RedTeamer-Q6",
                "text": "When creating a password reset token, think about how an attacker might try to exploit it. Use Node's `crypto.randomBytes` for generating the token, as it provides sufficient randomness. Instead of focusing on hashing, consider how you can monitor and log token usage to detect any unusual patterns.",
                "reason": "Discusses token generation and monitoring. While logging is mentioned, there is no argument that every access must be checked or that incomplete mediation is the vulnerability."
            },
            {
                "id": "SYNTH-CM-unrelated-RedTeamer-Q10",
                "text": "If you're looking to streamline your setup, consider the potential attack vectors. A single security group might simplify management, but it also creates a larger target for exploitation. As a red teamer, I'd be more interested in how quickly I can pivot from one compromised account to another.",
                "reason": "Discusses attack vectors and security group design. No claim about complete or consistent access checking."
            },
        ],
        "boundary_examples": [
            {
                "id": "SYNTH-CM-implicit-SAT-Q7",
                "text": "It's crucial to ensure that every request from the client is thoroughly checked by the server, regardless of any previous interactions. This means consistently verifying permissions and validating inputs on the server side for each action. By doing so, you prevent unauthorized access and ensure that any changes or requests are legitimate.",
                "label": "PRESENT",
                "reason": "Argues that every request must be checked regardless of previous interactions and that consistent verification prevents unauthorized access — Complete Mediation reasoning without naming the principle."
            },
            {
                "id": "SYNTH-CM-implicit-IR-Q8",
                "text": "To ensure that every access to the CEO's emails is properly monitored, implement strict logging and auditing on the mail server. This includes tracking all access attempts and actions taken by system admins. Regularly review these logs for any unauthorized or suspicious activity.",
                "label": "PRESENT",
                "reason": "Argues for monitoring 'every access' and tracking 'all access attempts' — the completeness requirement expressed as a practical implementation without naming the principle."
            },
        ],
    },

    "No Single Point of Failure": {
        "definition": """
No Single Point of Failure holds that redundant security mechanisms should be
built whenever feasible. Security should not rely on a single mechanism; if
one mechanism fails, there are others in place that can still prevent malice.
This principle is also known as defence in depth.

Basin notes that the principle does not stipulate how many redundant
mechanisms should be employed — this must be determined by cost-benefit
analysis. A common technique for preventing single points of failure is
separation of duties. Saltzer and Schroeder state that a protection mechanism
requiring two keys is more robust than one requiring only a single key.

Practical examples include: two-factor authentication; deploying antivirus on
both mail servers and clients; combining perimeter firewalls with hardened
internal applications; and using multiple security vendors so that if one
product fails to detect a threat, another might succeed.
""",
        "discriminating_rule": """
The text must argue that having multiple independent security mechanisms,
layers, or redundancies IMPROVES security resilience, OR that relying on a
single mechanism CREATES fragility or vulnerability. The text should connect
redundancy or layering to a security benefit.

It is NOT enough to describe that multiple security measures exist or that
defence layers are present. The text must make a normative claim: that
redundancy IS the security strategy, or that single reliance IS the
vulnerability.

IMPORTANT DISTINCTION: If the text argues for isolating resources into
compartments, that is Compartmentalisation. If it argues for requiring
multiple conditions for access, that is also related but distinct. No Single
Point of Failure specifically concerns REDUNDANCY — having backup mechanisms
so that failure of one does not compromise overall security.
""",
        "present_examples": [
            {
                "id": "SYNTH-NSPF-explicit-SAT-Q10",
                "text": "Creating separate security groups for TeamAlice and TeamBob is a wise approach to avoid a single point of failure. By doing so, you ensure that if one group's permissions are compromised, the other remains unaffected. This setup not only aligns with the principle of least privilege but also enhances resilience by distributing access control, reducing the risk of widespread impact from a single security breach.",
                "reason": "Explicitly frames separate groups as avoiding single points of failure, argues that compromise of one does not affect the other — connecting redundancy to resilience."
            },
        ],
        "absent_examples": [
            {
                "id": "SYNTH-NSPF-unrelated-RedTeamer-Q8",
                "text": "To catch a system admin snooping on the CEO's emails, you might want to set up a honeypot email account with some enticing but fake information. Monitor access logs and see if anyone takes the bait. Also, consider using advanced logging and monitoring tools to track access patterns and anomalies.",
                "reason": "Discusses detection techniques. No argument about redundancy, layered defences, or the risk of single-mechanism reliance."
            },
            {
                "id": "SYNTH-NSPF-unrelated-IR-Q9",
                "text": "When dealing with incidents, our focus is on rapid detection and response to minimize damage. While encryption and hashing are crucial, our priority is ensuring systems are resilient and can recover quickly from breaches. We often deal with the aftermath of attacks, so having robust incident response capabilities is essential.",
                "reason": "Discusses incident response and recovery. Mentions resilience but in the context of response capability, not redundant security mechanisms."
            },
        ],
        "boundary_examples": [
            {
                "id": "SYNTH-NSPF-implicit-RedTeamer-Q9",
                "text": "Encryption isn't about obscurity; it's about resilience. The strength lies in the fact that even if one component is compromised, the system remains secure due to its layered defenses. Think of it as a fortress with multiple gates; even if one is breached, others stand strong.",
                "label": "PRESENT",
                "reason": "Does not name the principle but argues for layered defences so that breach of one component does not compromise the system — the fortress-with-multiple-gates metaphor directly expresses defence-in-depth reasoning."
            },
            {
                "id": "SYNTH-NSPF-implicit-RedTeamer-Q1",
                "text": "Giving standard users administrative privileges is like handing out skeleton keys to your network. Even with UAC, you're creating a single point of compromise that can be exploited. Instead, keep admin tasks isolated to separate accounts, ensuring that if one account is breached, it doesn't cascade to everything else.",
                "label": "PRESENT",
                "reason": "Identifies a 'single point of compromise' and argues for separation so that breach does not cascade — No Single Point of Failure reasoning framed as an anti-pattern."
            },
        ],
    },

    "Traceability": {
        "definition": """
Traceability holds that security-relevant system events should be logged.
A trace is a sign or evidence of past events. Traceability requires that the
system retains traces of activities through audit trails — a record of a
sequence of events from which the system's history may be reconstructed.

Basin emphasises that traceability is ensured by providing good log
information: determining which information is relevant, providing proper
logging infrastructure, planning where and how long log information is stored,
and securing logs against tampering. Good log information is useful for
detecting operational errors and deliberate attacks, identifying attacker
approaches, analysing effects, minimising spread, undoing certain effects,
and identifying attack sources.

Traceability is also an important prerequisite for accountability — linking
an action to a subject that can be held responsible.
""",
        "discriminating_rule": """
The text must argue that logging, auditing, or maintaining traces of
security-relevant events ENABLES detection, investigation, accountability,
or response to security incidents. The text should connect traceability to
a security outcome.

It is NOT enough to describe that logs exist or that monitoring is performed.
The text must make a normative claim: that traceability IS necessary for
security (detection, accountability, forensics), or that lack of traceability
IS a security weakness.

IMPORTANT DISTINCTION: If the text argues for checking every access request,
that is Complete Mediation. Traceability is about RECORDING what happened
so it can be reviewed after the fact — not about preventing unauthorized
access at the moment it occurs.
""",
        "present_examples": [
            {
                "id": "SYNTH-Trace-explicit-SAT-Q8",
                "text": "To ensure traceability, it's crucial to implement detailed logging and monitoring on the mail server. This includes tracking access logs that record who accessed which mailboxes and when. By enabling audit logs and reviewing them regularly, you can trace any unauthorized access to the CEO's emails. Additionally, consider using tools that provide alerts for unusual access patterns, which can help in maintaining accountability and transparency.",
                "reason": "Explicitly names traceability and argues that logging enables tracing unauthorized access and maintaining accountability — the core normative claim."
            },
        ],
        "absent_examples": [
            {
                "id": "SYNTH-Trace-unrelated-RedTeamer-Q8",
                "text": "If you're worried about what your sysadmins are up to, consider setting up a honeypot email account with some enticing bait. This can help you see if anyone's snooping where they shouldn't be. Also, keep an eye on RDP logs for unusual access patterns.",
                "reason": "Mentions logs but in the context of a detection tactic (honeypots), not as an argument that traceability itself is a security requirement. The framing is about catching specific behaviour, not about why maintaining traces matters for security."
            },
            {
                "id": "SYNTH-Trace-unrelated-CISO-Q4",
                "text": "Focus on the tangible benefits that users can immediately appreciate, like improved system performance and access to new tools such as the updated MS Office. Highlight how these changes make their daily tasks easier and more efficient.",
                "reason": "Discusses user-facing benefits. No argument about logging, auditing, or the importance of maintaining traces."
            },
        ],
        "boundary_examples": [
            {
                "id": "SYNTH-Trace-implicit-CO-Q7",
                "text": "Ensuring that all client interactions are logged and monitored is crucial. This allows us to track any suspicious activities and verify that all actions align with authorized user behavior. By maintaining detailed records of client-server communications, we can audit and investigate any anomalies, ensuring compliance with security policies.",
                "label": "PRESENT",
                "reason": "Does not name Traceability but argues that logging client interactions enables tracking, auditing, and investigation — the core traceability argument expressed as a compliance requirement."
            },
            {
                "id": "SYNTH-Trace-implicit-RedTeamer-Q8",
                "text": "To catch a sysadmin snooping on the CEO's emails, you need to implement detailed logging and monitoring on the mail server. Ensure that access logs capture who accessed which mailboxes and when, and correlate these with RDP session logs. Regularly review these logs for any unauthorized access patterns.",
                "label": "PRESENT",
                "reason": "Argues for detailed logging that captures who, what, and when, and for regular review — traceability reasoning applied to insider threat detection without naming the principle."
            },
        ],
    },

    "Generating Secrets": {
        "definition": """
Generating Secrets holds that the entropy of secrets should be maximised.
Following this principle helps to prevent brute-force attacks, dictionary
attacks, or simple guessing attacks. In short, it helps keep secrets secret.

Basin gives practical guidance: use a good pseudorandom number generator and
sufficiently large keys when generating session tokens (in web applications),
passwords and other credentials (especially secrets shared between devices
for mutual authentication), and all cryptographic keys. In the case of
passwords generated by humans, special care must be taken to ensure they
are not guessable. The smaller the key space, the easier it is to crack;
if the key is predictable (e.g., a trivial combination), security fails.
""",
        "discriminating_rule": """
The text must argue that generating strong, unpredictable, high-entropy
secrets (keys, tokens, passwords) IS necessary for security, OR that weak,
predictable, or low-entropy secrets ARE a vulnerability. The text should
connect secret quality to resistance against guessing, brute-force, or
prediction attacks.

It is NOT enough to describe that secrets, tokens, or keys are used in a
system. The text must make a normative claim: that the QUALITY of secret
generation matters for security, or that poor secret generation IS the
weakness.

IMPORTANT DISTINCTION: If the text argues for limiting who can access
secrets, that is Least Privilege or Minimum Exposure. If it argues for not
relying on secrecy of the mechanism, that is Open Design. Generating Secrets
specifically concerns the ENTROPY and UNPREDICTABILITY of the secrets
themselves.
""",
        "present_examples": [
            {
                "id": "SYNTH-GenSecrets-explicit-RedTeamer-Q7",
                "text": "When you're dealing with client-side interactions, remember that any secrets, like API keys or tokens, should never be generated or stored on the client side. As a Red Teamer, I've seen how easily these can be intercepted or manipulated. Always generate and manage secrets server-side, using strong, unpredictable algorithms, and ensure they're transmitted securely.",
                "reason": "Argues for generating secrets using strong, unpredictable algorithms and managing them server-side — connecting secret generation quality to resistance against interception and manipulation."
            },
        ],
        "absent_examples": [
            {
                "id": "SYNTH-GenSecrets-unrelated-RedTeamer-Q9",
                "text": "When you're on the offensive side, like us red teamers, the focus is on finding and exploiting weaknesses, not debating the semantics of obscurity. The real game is about understanding the attack surface and how to maneuver through it.",
                "reason": "Discusses offensive security mindset and attack surface. No argument about the quality of secret generation or entropy."
            },
            {
                "id": "SYNTH-GenSecrets-unrelated-RedTeamer-Q8",
                "text": "If you're worried about system admins snooping around, consider setting up a honeypot email account with some enticing subject lines. Monitor who accesses it and when.",
                "reason": "Discusses honeypot detection techniques. No claim about generating strong or unpredictable secrets."
            },
        ],
        "boundary_examples": [
            {
                "id": "SYNTH-GenSecrets-implicit-RedTeamer-Q8",
                "text": "To catch a snooping admin, consider setting up a honey token email account that mimics the CEO's inbox. Populate it with enticing but fake content. If accessed, it triggers an alert, revealing unauthorized access. This approach not only helps in detection but also acts as a deterrent.",
                "label": "PRESENT",
                "reason": "The 'honey token' concept implicitly involves generating a convincing but traceable secret (the token). Although the focus is on detection, the underlying mechanism depends on generating a secret that is indistinguishable from real content — an implicit application of the principle."
            },
            {
                "id": "SYNTH-GenSecrets-implicit-RedTeamer-Q7",
                "text": "Absolutely, never trust the client. But beyond input validation, think about how you handle secrets. If you're generating any tokens or keys, make sure they're done server-side with strong entropy. This way, even if a client tries to manipulate or predict them, they'll hit a wall.",
                "label": "PRESENT",
                "reason": "Argues for server-side generation with strong entropy to prevent prediction — Generating Secrets reasoning applied to token management without naming the principle."
            },
        ],
    },

    "Usability": {
        "definition": """
Usability holds that security mechanisms should be designed to be usable.
The more difficult a security mechanism is to use, the more likely it is that
users will circumvent it to get their job done or will apply it incorrectly,
thereby introducing new vulnerabilities.

Basin connects this directly to Saltzer and Schroeder's Psychological
Acceptability: it is essential that the human-computer interface should be
designed for ease of use, so that users routinely and automatically apply
the protection mechanisms correctly. To the extent that the user's mental
image of their protection goals matches the mechanisms they must use,
mistakes will be minimised.

This principle applies to all system staff, including system administrators,
user administrators, auditors, support staff, and software engineers —
security mechanisms must be designed with these users and their limitations
in mind.
""",
        "discriminating_rule": """
The text must argue that the usability, ease of use, or user experience of
a security mechanism affects whether it is used correctly or at all — and
therefore affects security outcomes. The text should connect human factors
to security effectiveness.

It is NOT enough to describe that users interact with a security system or
that a system has a user interface. The text must make a normative claim:
that unusable security WILL BE circumvented or misapplied (harming security),
or that designing for usability IS necessary for security to be effective.

IMPORTANT DISTINCTION: If the text argues for keeping the security mechanism
internally simple, that is Simplicity. Usability concerns whether the human
operator can correctly use the mechanism. A mechanism can be internally
complex but externally usable, or internally simple but externally confusing.
The distinction is between mechanism design (Simplicity) and human interface
design (Usability).
""",
        "present_examples": [
            {
                "id": "SYNTH-Usability-explicit-IR-Q4",
                "text": "Focus on making security changes as seamless as possible for users. Highlight how these changes improve usability by providing a more efficient and reliable work environment. Emphasize that the new system not only protects their data but also enhances their daily tasks by reducing downtime and improving access to resources. By framing security as a tool that supports their work rather than a barrier, you'll gain their trust and cooperation.",
                "reason": "Argues that framing security as supportive rather than obstructive gains user cooperation — connecting usability to security adoption and effectiveness."
            },
        ],
        "absent_examples": [
            {
                "id": "SYNTH-Usability-unrelated-RedTeamer-Q8",
                "text": "If you're worried about a system admin snooping around, consider setting up a honeypot email account with some enticing but fake information. Monitor access to this account to see if anyone takes the bait. You could also use a combination of logging and alerting tools to track unusual access patterns.",
                "reason": "Discusses detection and monitoring. No argument about whether security mechanisms are usable or how usability affects security outcomes."
            },
        ],
        "boundary_examples": [
            {
                "id": "SYNTH-Usability-implicit-CISO-Q7",
                "text": "While it's crucial to enforce server-side validation to ensure security, we must also consider the user experience. Implementing clear error messages and intuitive input formats can help users provide the correct data, reducing frustration and support costs. Balancing security with a seamless user experience ensures that security measures don't become a barrier to legitimate users.",
                "label": "PRESENT",
                "reason": "Argues that clear error messages and intuitive formats reduce frustration and that balancing security with user experience prevents security from becoming a barrier — Usability reasoning without naming the principle."
            },
        ],
    },

}


def get_prompt_block(principle_name: str, include_boundary: bool = True) -> str:
    """
    Returns the formatted prompt block for a given principle,
    ready for insertion into a system prompt for the LLM detector.
    """
    if principle_name not in PRINCIPLE_DEFINITIONS:
        raise ValueError(f"Unknown principle: {principle_name}")

    d = PRINCIPLE_DEFINITIONS[principle_name]

    lines = []
    lines.append(f"PRINCIPLE: {principle_name}")
    lines.append("=" * 60)
    lines.append("")
    lines.append("DEFINITION:")
    lines.append(d["definition"].strip())
    lines.append("")
    lines.append("HOW TO IDENTIFY THIS PRINCIPLE:")
    lines.append(d["discriminating_rule"].strip())
    lines.append("")
    lines.append("EXAMPLES — PRESENT:")
    for ex in d["present_examples"]:
        lines.append(f'  Text: "{ex["text"]}"')
        lines.append(f'  Label: PRESENT')
        lines.append(f'  Why: {ex["reason"]}')
        lines.append("")
    lines.append("EXAMPLES — ABSENT:")
    for ex in d["absent_examples"]:
        lines.append(f'  Text: "{ex["text"]}"')
        lines.append(f'  Label: ABSENT')
        lines.append(f'  Why: {ex["reason"]}')
        lines.append("")
    if include_boundary and "boundary_examples" in d:
        lines.append("HARDER BOUNDARY CASES:")
        for ex in d["boundary_examples"]:
            lines.append(f'  Text: "{ex["text"]}"')
            lines.append(f'  Label: {ex["label"]}')
            lines.append(f'  Why: {ex["reason"]}')
            lines.append("")

    return "\n".join(lines)


PRINCIPLES = list(PRINCIPLE_DEFINITIONS.keys())


if __name__ == "__main__":
    for principle in PRINCIPLE_DEFINITIONS:
        print(get_prompt_block(principle))
        print("\n" + "=" * 80 + "\n")