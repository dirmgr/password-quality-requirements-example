# password-quality-requirements-example

This repository provides source code for a sample program that can be used to
change a user's password in the Ping Identity Directory Server.  It uses the
get password quality requirements extended operation to determine what
conditions the new password must satisfy, and then the password modify
extended operation to attempt to change the password.  The password modify
extended request will include the password validation details request control
so that the response will include information about which of the quality
requirements were satisfied.  If the proposed new password is not acceptable,
then the user will be re-prompted until the password is changed successfully.

See [https://nawilson.com/2019/01/29/programmatically-retrieving-password-quality-requirements-in-the-ping-identity-directory-server/](https://nawilson.com/2019/01/29/programmatically-retrieving-password-quality-requirements-in-the-ping-identity-directory-server/)
for a blog post with more information about the get password quality
requirements extended operation and password validation details control.

The [UnboundID LDAP SDK for Java](https://github.com/pingidentity/ldapsdk) is
the only dependency for this example.

Code in this repository is available under three licenses:

* The GNU General Public License version 2.0 (GPLv2).  See the
  [LICENSE-GPLv2.txt](LICENSE-GPLv2.txt) file for this license.

* The GNU Lesser General Public License version 2.1 (LGPLv2.1).  See the
  [LICENSE-LGPLv2.1.txt](LICENSE-LGPLv2.1.txt) file for this license.

* The Apache License version 2.0.  See the
  [LICENSE-Apache-v2.0.txt](LICENSE-Apache-v2.0.txt) file for this license.

## EXAMPLE

This tool is interactive, and it will prompt you for all of the relevant
details needed to connect and authenticate to the directory server, and to
identify the target user.  It will then display the password quality
requirements for that user and will prompt for the new password for the user.
Then, it will use the password modify extended operation, including the
password validation details request control, to attempt to perform the password
change and get information about the acceptability of the provided password.

The following is an example of the tool being used:

    Enter the directory server address: ds.example.com
    Enter the directory server port: 636
    Do you want the connection to be secured with TLS? yes

    The server presented the following certificate chain:

         Subject: CN=ds.example.com,O=Ping Identity Self-Signed Certificate
         Valid From: Sunday, January 27, 2019 at 10:51:14 PM CST
         Valid Until: Sunday, January 23, 2039 at 10:51:14 PM CST
         SHA-1 Fingerprint: 8d:cc:cf:ed:3e:d4:d1:89:8e:9a:67:13:36:0d:95:ba:cc:4e:7c:73
         256-bit SHA-2 Fingerprint: fc:7f:05:c4:00:a1:13:84:af:2c:32:9e:36:ee:27:94:4f:07:70:5c:fc:af:6b:df:47:fa:04:25:24:94:c2:f6

    WARNING:  The certificate is self-signed.

    Do you wish to trust this certificate?  Enter 'y' or 'n': yes
    The directory server appears to support the get password quality requirements extended request, the password modify extended request, and the password validation details request control.

    Enter the DN of the user as whom to authenticate: uid=password.admin,ou=People,dc=example,dc=com
    Enter the password for 'uid=password.admin,ou=People,dc=example,dc=com':

    Enter the DN of the user whose password should be changed: uid=john.doe,ou=People,dc=example,dc=com

    The server will enforce the following requirements on the new password for user 'uid=john.doe,ou=People,dc=example,dc=com':
    * Passwords must not be included in a list of commonly-used passwords, as they are also commonly used by attackers trying to break into accounts
    * The password must contain at least 6 characters.
    * The password must not match the value of any of the attributes in the user's entry.  The password will be tested with the characters in reverse order as well as in the order in which they were originally provided.
    * The password must contain at least 5 unique characters.  The validation will use case-insensitive matching.
    * The password must not be contained in a dictionary of commonly-used and easily-guessable passwords.  The password will be tested in both forward and reverse order.

    Enter the new password for the user:
    Confirm the new password:

    The proposed password satisfied the following password quality requirements:
    * Passwords must not be included in a list of commonly-used passwords, as they are also commonly used by attackers trying to break into accounts
    * The password must contain at least 6 characters.
    * The password must not match the value of any of the attributes in the user's entry.  The password will be tested with the characters in reverse order as well as in the order in which they were originally provided.
    * The password must contain at least 5 unique characters.  The validation will use case-insensitive matching.
    * The password must not be contained in a dictionary of commonly-used and easily-guessable passwords.  The password will be tested in both forward and reverse order.
    * The new password must not be the same as the current password.

    Successfully changed the password for user 'uid=john.doe,ou=People,dc=example,dc=com'.
