#Scope
##Technical Scope
Safe Places web services, hosted at hermes (mobile app facing) and zeus (HA facing).

Used the following references
[OWASP Testing for Session Managemnet](https://www.owasp.org/index.php/Testing_for_Session_Management).
[OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
[JWT Attack Playbook](https://github.com/ticarpi/jwt_tool/wiki)
[RFC 8725](https://datatracker.ietf.org/doc/rfc8725/?include_text=1)
[jsonwebtoken docs](https://github.com/auth0/node-jsonwebtoken)

## 2.10 Service Authentication Requirements

* Verify that integration secrets do not rely on unchanging passwords, such as API keys or shared privileged accounts.

__A username and password is provided for the authenticated APIs.  In this example spladmin/ password.  The actual authentication is just a reference LDAP implementation so out of scope of this review.  A JWT token is provided based on successful authentication.  No "hardcoded" secret is used.  This was verified on each documented API.__

* Verify that if passwords are required, the credentials are not a default account.

__Verified with environments team that they specifically added the user__

* Verify that passwords are stored with sufficient protection to prevent offline recovery attacks, including local system access.

__Not applicable, descoping__

* Verify passwords, integrations with databases and third-party systems, seeds and internal secrets, and API keys are managed securely and not included in the source code or stored within source code repositories. Such storage SHOULD resist offline attacks. The use of a secure software key store (L1), hardware trusted platform module (TPM), or a hardware security module (L3) is recommended for password storage.

__Verified as envirnment variables.__


## 3.2 Session Binding Requirements

* Verify the application generates a new session token on user authentication.

__Checked that a new token is generated on each auth.  Checked the jsonwebtoken library is used and the version used has [no CVEs](https://www.cvedetails.com/product/61276/Auth0-Jsonwebtoken.html?vendor_id=17859)__

* Verify that session tokens possess at least 64 bits of entropy.

__Additionally, checked 5 sequential tokens for entropy.  I used the script in this folder called TokenEntropy.py to do this.  I discovered that 45-47 bits of entropy is present in each new token, rather than the required 64.  [Raised in Jira](https://pathcheck.atlassian.net/browse/PLACES-321)__

* Verify the application only stores session tokens in the browser using secure methods such as appropriately secured cookies (see section 3.4) or HTML 5 session storage.

__Failed this test it is [stored in local storage instead of session](https://pathcheck.atlassian.net/browse/PLACES-323) and [doesn't have a fingerprint](https://pathcheck.atlassian.net/browse/PLACES-324)__

* Verify that session token are generated using approved cryptographic algorithms.

__HMAC 256 is used as recommended by the OWASP cheat sheet__


## 3.3 Session Logout and Timeout Requirements
* Verify that logout and expiration invalidate the session token, such that the back button or a downstream relying party does not resume an authenticated session, including across relying parties

__[Failed and raised as jira](https://pathcheck.atlassian.net/browse/PLACES-325).  I copied the persist:root values from local storage to clipboard, logged out, pasted the data back in, then was able to reaccess the trace screen without logging back in__

* If authenticators permit users to remain logged in, verify that re-authentication occurs periodically both when actively used or after an idle period

__Observed in the [code](https://github.com/Path-Check/safeplaces-backend/blob/253da374c84bf1921edc5e4bc19ce19f9d726666/app/api/auth/controller.js) that this is set to 1 hr__

* Verify that the application terminates all other active sessions after a successful password change, and that this is effective across the application, federated login (if present), and any relying parties.

__This is not directly supported, but note that the token would expire in 1 hour.  Not raised as an issue given we are not implementing or binding to a specific ID management solution__

* Verify that users are able to view and log out of any or all currently active sessions and devices.

__Opened two browsers, logged in with the same account. Logged out in one, the other was able to proceed.  [Raised](https://pathcheck.atlassian.net/browse/PLACES-326) as low priority.__


## 3.5 Token Based Session Management
* Verify the application does not treat OAuth and refresh tokens — on their own — as the presence of the subscriber and allows users to terminate trust relationships with linked applications.

__Not applicable, removing from principles__

* Verify the application uses session tokens rather than static API secrets and keys, except with legacy implementations.

__Verified__

* Verify that stateless session tokens use digital signatures, encryption, and other countermeasures to protect against tampering, enveloping, replay, null cipher, and key substitution attacks.

__Marking as failed due to issues mentioned above__
