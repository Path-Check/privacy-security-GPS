Privacy And Security

Privacy and security each repreasents a separate knowledge and work domain. Privacy and security intersect and support each other. Privacy cannot be achieved without appropriate security protections. At the same time, reasonable security helps to ensure some of privacy's primary goals, especially, data protection.

For clarity, there are privacy objectives that have little or nothing to do with security. For instance gaining consent for data collection and use in and of itself, has no security aspect (though the implementation of it in software will likely have tangential security requirements just as any data input will).

Likewise, there are security objectives which are not directly related to privacy requirements. An appropriate and relevant defense-in-depth will help to ensure privacy's defensive necessities. As an example, consider the security objective to remove as many implementation errors that may offer attacker leverage (commonly called, "vulnerabilities") as possible before release of software, particularly, as in Path-Check, where software will be released to potentially large populations, i.e., the general public. Some vulnerabilities will offer attackers opportunities to breach privacy protections, though many types of vulnerabilites will not, directly.

Privacy and security are separate knowledge and skill domains. There is an intersection between the two domains.

Privacy will require security protections for privacy data processing, data in transit, and data at rest. Furthermore, privacy may require security functions like authentication to assure an entity before allowing it access to data that has privacy requirements. Likewise, privacy must require authorization to ensure that only the authenticated entity may access the allowed data (please see SecurityImplementation.md for greater detail on security features). Privacy, thus, has security "requirements" that must be fulfilled through security protections, i.e., are a part of an holistic defense-in-depth.

Security supports privacy. Privacy cannot be achieved without security measures.

At the same time, as noted, holistic security practices as described in SecurityImplementation.md provide a foundation upon which, privacy rests. Though server security, or implementation errors (coding errors) may not specifically be required by privacy, these must be assumed, since attackers commonly piece together bits of leverage in exploitable steps towards their goals. Some of that leverage (exploits against weakenesses and vulnerabilities) may appear to have little to do with privacy. But taken together, the entire set of steps (a "kill chain") can result in a privacy breach.

Due to the intersectiona and supporting nature of the relationship of privacy and security, Safe Paths has defined both privacy and security principles to guide software design, development, and release. Please see the other documents in this area for more detail.
