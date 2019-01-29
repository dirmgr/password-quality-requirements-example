/*
 * Copyright 2019 Neil A. Wilson
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019 Neil A. Wilson
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
/*
 * Copyright 2019 Neil A. Wilson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.dirmgr.example.pwquality;



import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordQualityRequirementValidationResult;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordValidationDetailsRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordValidationDetailsResponseControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            GetPasswordQualityRequirementsExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            GetPasswordQualityRequirementsExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.extensions.PasswordQualityRequirement;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ssl.AggregateTrustManager;
import com.unboundid.util.ssl.JVMDefaultTrustManager;
import com.unboundid.util.ssl.PromptTrustManager;
import com.unboundid.util.ssl.SSLUtil;



/**
 * This class provides an interactive command-line tool that can be used to
 * change a user's password in a Ping Identity Directory Server instance.  It
 * can be used either to perform a self change (in which a user changes their
 * own password) or an administrative reset (in which one user changes the
 * password for another user).  It also serves as an example that demonstrates
 * the use of the get password quality requirements extended operation to
 * retrieve information about the constraints that the password will be
 * required to satisfy before prompting for the user's new password, and the
 * password validation details control to obtain information from the server
 * about how well the proposed met each of those requirements.  The password
 * modify extended operation will be used to actually change the user's
 * password.
 */
public class ChangeUserPassword
{
  /**
   * Runs this program with the provided set of arguments.
   *
   * @param  args  The command-line arguments provided to this program.  This
   *               program obtains all of the necessary information
   *               interactively and therefore does not require any command-line
   *               arguments.
   */
  public static void main(final String... args)
  {
    final BufferedReader in =
         new BufferedReader(new InputStreamReader(System.in));

    try (LDAPConnection connection = getLDAPConnection(in))
    {
      System.out.println();
      checkRootDSE(connection);

      System.out.println();
      final ObjectPair<DN,String> bindDNAndPassword = bind(connection, in);

      System.out.println();
      final DN targetDN = readDN(
           "Enter the DN of the user whose password should be changed: ", in);
      final boolean isSelfChange =
           targetDN.equals(bindDNAndPassword.getFirst());

      final GetPasswordQualityRequirementsExtendedResult gpqrResult =
           displayPasswordQualityRequirements(connection, targetDN,
                isSelfChange);

      changePassword(connection, bindDNAndPassword, targetDN);
    }
  }



  /**
   * Establishes a connection to an LDAP directory server.
   *
   * @param  in  The buffered reader to use to read from standard input.
   *
   * @return  The connection that was established.
   */
  private static LDAPConnection getLDAPConnection(final BufferedReader in)
  {
    while (true)
    {
      final String address = readLine(
           "Enter the directory server address: ", in);
      final int port = readInteger("Enter the directory server port: ", 1,
           65535, in);

      final boolean secure = readBoolean(
           "Do you want the connection to be secured with TLS? ", in);

      if (secure)
      {
        try
        {
          final SSLUtil sslUtil = new SSLUtil(new AggregateTrustManager(false,
               JVMDefaultTrustManager.getInstance(), new PromptTrustManager()));
          return new LDAPConnection(sslUtil.createSSLSocketFactory(), address,
               port);
        }
        catch (final Exception e)
        {
          System.err.println("ERROR: Unable to establish a secure " +
               "connection to " + address + ':' + port + ": " +
               StaticUtils.getExceptionMessage(e));
          System.err.println();
        }
      }
      else
      {
        try
        {
          return new LDAPConnection(address, port);
        }
        catch (final Exception e)
        {
          System.err.println(
               "ERROR: Unable to establish an LDAP connection to " +
                    address + ':' + port + ": " +
                    StaticUtils.getExceptionMessage(e));
          System.err.println();
        }
      }
    }
  }



  /**
   * Checks the directory server root DSE to ensure that it claims to support
   * the get password quality requirements extended operation, the password
   * modify extended operation, and the password validation details request
   * control.  If we can retrieve the root DSE but can't verify support, then
   * display a warning message.  If we cannot retrieve the root DSE, then don't
   * complain because the server may prohibit anonymous requests, even when
   * targeting the root DSE.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   */
  private static void checkRootDSE(final LDAPConnection connection)
  {
    final RootDSE rootDSE;
    try
    {
      rootDSE = connection.getRootDSE();
      if (rootDSE == null)
      {
        // This is fine.  The root DSE might not be accessible over an
        // unauthenticated connection.
        return;
      }
    }
    catch (final Exception e)
    {
      // This is fine.  The root DSE might not be accessible over an
      // unauthenticated connection.
      return;
    }


    boolean warned = false;
    if (! rootDSE.supportsExtendedOperation(
         GetPasswordQualityRequirementsExtendedRequest.
              OID_GET_PASSWORD_QUALITY_REQUIREMENTS_REQUEST))
    {
      warned = true;
      System.err.println();
      System.err.println("WARNING: The directory server root DSE does not " +
           "claim support for the get password quality requirements " +
           "extended operation.  This tool requires support for that " +
           "operation.");
    }

    if (! rootDSE.supportsExtendedOperation(
         PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID))
    {
      warned = true;
      System.err.println();
      System.err.println("WARNING: The directory server root DSE does not " +
           "claim support for the password modify extended operation.  This " +
           "tool requires support for that operation.");
    }

    if (! rootDSE.supportsControl(PasswordValidationDetailsRequestControl.
         PASSWORD_VALIDATION_DETAILS_REQUEST_OID))
    {
      warned = true;
      System.err.println();
      System.err.println("WARNING: The directory server root DSE does not " +
           "claim support for the password validation details request " +
           "control.  This tool requires support for that control.");
    }

    if (! warned)
    {
      System.out.println("The directory server appears to support the " +
           "get password quality requirements extended request, the " +
           "password modify extended request, and the password validation " +
           "details request control.");
    }
  }



  /**
   * Performs a bind operation to authenticate to the directory server.
   *
   * @param  connection  The connection to use to communicate with the directory
   *                     server.
   * @param  in          The buffered reader to use to read from standard input.
   *
   * @return  An {@code ObjectPair} in which the first element is the DN of the
   *          user that authenticated, and the second element is the bind
   *          password.
   */
  private static ObjectPair<DN,String> bind(final LDAPConnection connection,
                                            final BufferedReader in)
  {
    while (true)
    {
      final DN bindDN = readDN(
           "Enter the DN of the user as whom to authenticate: ", in);

      final String password = readPassword(
           "Enter the password for '" + bindDN + "': ");

      try
      {
        connection.bind(bindDN.toString(), password);
        return new ObjectPair<>(bindDN, password);
      }
      catch (final Exception e)
      {
        System.err.println("ERROR: Unable to bind as user '" + bindDN +
             "' with the provided password: " +
             StaticUtils.getExceptionMessage(e));
        System.err.println();
      }
    }
  }



  /**
   * Retrieves and displays the password quality requirements for the specified
   * user.
   *
   * @param  connection    The connection to use to communicate with the
   *                       directory server.
   * @param  userDN        The DN of the user whose password is being changed.
   * @param  isSelfChange  Indicates whether the user is changing their own
   *                       password (if {@code true}) or resetting the password
   *                       for another user (if {@code false}).
   *
   * @return  The get password quality requirements extended result returned by
   *          the server.
   */
  private static GetPasswordQualityRequirementsExtendedResult
                      displayPasswordQualityRequirements(
                           final LDAPConnection connection, final DN userDN,
                           final boolean isSelfChange)
  {
    final GetPasswordQualityRequirementsExtendedRequest gpqrRequest;
    if (isSelfChange)
    {
      gpqrRequest = GetPasswordQualityRequirementsExtendedRequest.
           createSelfChangeForSpecifiedUserRequest(userDN.toString());
    }
    else
    {
      gpqrRequest = GetPasswordQualityRequirementsExtendedRequest.
           createAdministrativeResetForSpecifiedUserRequest(userDN.toString());
    }

    GetPasswordQualityRequirementsExtendedResult gpqrResult;
    try
    {
      gpqrResult = (GetPasswordQualityRequirementsExtendedResult)
           connection.processExtendedOperation(gpqrRequest);
    }
    catch (final LDAPException le)
    {
      try
      {
        gpqrResult = new GetPasswordQualityRequirementsExtendedResult(
             new ExtendedResult(le));
      }
      catch (final Exception e)
      {
        throw new RuntimeException(
             "ERROR: Unable to parse non-success get password quality " +
                  "requirements response " + le.toLDAPResult() + ": " +
                  StaticUtils.getExceptionMessage(e),
             e);
      }
    }

    if (gpqrResult.getResultCode() != ResultCode.SUCCESS)
    {
      throw new RuntimeException(
           "ERROR: Unable to use the get password quality requirements " +
                "extended operation to retrieve the requirements for user '" +
                userDN + "':  " + gpqrResult);
    }

    System.out.println();
    final List<PasswordQualityRequirement> requirements =
         gpqrResult.getPasswordRequirements();
    if ((requirements == null) || requirements.isEmpty())
    {
      System.out.println("The server will not enforce any validation " +
           "requirements on the new password for user '" + userDN + "'.");
    }
    else
    {
      System.out.println("The server will enforce the following requirements " +
           "on the new password for user '" + userDN + "':");
      for (final PasswordQualityRequirement requirement : requirements)
      {
        System.out.println("* " + requirement.getDescription());
      }
    }

    System.out.println();

    if (gpqrResult.getMustChangePassword() == Boolean.TRUE)
    {
      System.out.println(
           "NOTE: The user will be required to change their password the " +
                "next time they authenticate.");
      System.out.println();
    }

    final Integer secondsValid = gpqrResult.getSecondsUntilExpiration();
    if ((secondsValid != null) && (secondsValid > 0))
    {
      System.out.println("NOTE: The new password will be valid for " +
           StaticUtils.secondsToHumanReadableDuration(secondsValid) + '.');
      System.out.println();
    }

    return gpqrResult;
  }



  /**
   * Reads the new password that should be set for the user.
   *
   * @return  The new password that should be set for the user.
   */
  private static String readNewPassword()
  {
    while (true)
    {
      final String newPassword =
           readPassword("Enter the new password for the user: ");

      // TODO: Perform client-side validation for the new password.

      final String confirmedPassword =
           readPassword("Confirm the new password: ");
      if (newPassword.equals(confirmedPassword))
      {
        return newPassword;
      }
      else
      {
        System.err.println("ERROR: The provided passwords do not match.");
        System.err.println();
      }
    }
  }



  /**
   * Attempts to change the password using the provided information.
   *
   * @param  connection         The connection to use to communicate with the
   *                            directory server.
   * @param  bindDNAndPassword  The bind DN and password for the user that is
   *                            currently authenticated on the connection.
   * @param  targetDN           The DN of the user whose password is being
   *                            changed.
   *
   * @return  The result code from the password change attempt.
   */
  private static ResultCode changePassword(final LDAPConnection connection,
                                 final ObjectPair<DN,String> bindDNAndPassword,
                                 final DN targetDN)
  {
    while (true)
    {
      // Get the proposed new password for the user.
      final String newPassword = readNewPassword();


      // Construct a password modify extended request to the directory server.
      // Make sure to include a password validation details request control.
      final String oldPassword;
      if (bindDNAndPassword.getFirst().equals(targetDN))
      {
        oldPassword = bindDNAndPassword.getSecond();
      }
      else
      {
        oldPassword = null;
      }

      final Control[] requestControls =
      {
        new PasswordValidationDetailsRequestControl()
      };


      // Send the password modify extended request and read the response.
      final PasswordModifyExtendedRequest passwordModifyRequest =
           new PasswordModifyExtendedRequest("dn:" + targetDN, oldPassword,
                newPassword, requestControls);

      PasswordModifyExtendedResult passwordModifyResult;
      try
      {
        passwordModifyResult = (PasswordModifyExtendedResult)
             connection.processExtendedOperation(passwordModifyRequest);
      }
      catch (final LDAPException le)
      {
        try
        {
          passwordModifyResult = new PasswordModifyExtendedResult(
               new ExtendedResult(le));
        }
        catch (final Exception e)
        {
          throw new RuntimeException(
               "ERROR:  The password modify extended operation failed with " +
                    "result " + le.toLDAPResult() + ", and the server " +
                    "response could not be parsed as a password modify " +
                    "extended result: " + StaticUtils.getExceptionMessage(e),
               e);
        }
      }


      // Get the password validation details response control from the result,
      // if possible.
      final PasswordValidationDetailsResponseControl pwvdResponse;
      try
      {
         pwvdResponse =
             PasswordValidationDetailsResponseControl.get(passwordModifyResult);
      }
      catch (final Exception e)
      {
        throw new RuntimeException(
             "ERROR: An error occurred while trying to retrieve the " +
                  "password validation details response control from " +
                  "password modify extended result " + passwordModifyResult +
                  StaticUtils.getExceptionMessage(e),
             e);
      }

      if (pwvdResponse == null)
      {
        if (passwordModifyResult.getResultCode() == ResultCode.SUCCESS)
        {
          throw new RuntimeException(
               "ERROR: The password for user '" + targetDN +
                    "' was changed successfully, but password modify " +
                    "extended result " + passwordModifyResult +
                    " returned by the server did not include the expected " +
                    "password validation details response control.");
        }
        else
        {
          System.err.println("ERROR: The password modify extended operation " +
               "failed with result " + passwordModifyResult +
               ". The response did not include a password validation details " +
               "response control, so it is likely the case that the attempt " +
               "failed for some reason other than the quality of the " +
               "proposed password.");
        }

        return passwordModifyResult.getResultCode();
      }


      // Look at the response type.  We know that we provided exactly one
      // password, so a couple of the options aren't really relevant.  We should
      // either have validation results, or the operation failed before
      // validation could be attempted.
      switch (pwvdResponse.getResponseType())
      {
        case VALIDATION_DETAILS:
          // We'll take care of this later.
          break;

        case NO_VALIDATION_ATTEMPTED:
          if (passwordModifyResult.getResultCode() == ResultCode.SUCCESS)
          {
            System.out.println("The password for user '" + targetDN +
                 "' was successfully changed, but no validation was " +
                 "attempted.  This may mean that the password policy for " +
                 "that user is not configured with any password validators " +
                 "that apply to this operation.");
          }
          else
          {
            System.err.println("ERROR: The password for user '" + targetDN +
                 "' could not be changed.  Password validation details " +
                 "response control " + pwvdResponse + " included in " +
                 "password modify result " + passwordModifyResult +
                 " indicates that no validation was attempted, so it is " +
                 "like that the password change attempt failed for some " +
                 "reason other than the quality of the password.");
          }
          return passwordModifyResult.getResultCode();

        case NO_PASSWORD_PROVIDED:
        case MULTIPLE_PASSWORDS_PROVIDED:
        default:
          throw new RuntimeException(
               "ERROR: An unexpected response type of " +
                    pwvdResponse.getResponseType().name() +
                    " was found in password validation details response " +
                    "control " + pwvdResponse + " included in password " +
                    "modify extended result " + passwordModifyResult +
                    ".  The only expected response types were " +
                    "VALIDATION_DETAILS or NO_VALIDATION_ATTEMPTED.");
      }


      // Display the password validation details from the response.  If the
      // operation was successful, then we're done.  Otherwise, continue so that
      // we can prompt for a different password.
      final ResultCode resultCode = passwordModifyResult.getResultCode();
      displayPasswordValidationDetails(resultCode, pwvdResponse);

      if (resultCode == ResultCode.SUCCESS)
      {
        System.out.println();
        System.out.println("Successfully changed the password for user '" +
             targetDN + "'.");
        return ResultCode.SUCCESS;
      }
      else
      {
        System.err.println();
        System.err.println("The proposed password was not accepted by the " +
             "server. Please try again.");
      }
    }
  }



  /**
   * Displays the information from a password validation details response
   * control.  This should only be used for a password validation response type
   * of {@code VALIDATION_DETAILS}.
   *
   * @param  resultCode   The result code for the password modify extended
   *                      operation.  This will be used to determine whether to
   *                      write to standard output (if successful) or standard
   *                      error (if unsuccessful).
   * @param  pvdResponse  The password validation details response control to
   *                      display.
   */
  private static void displayPasswordValidationDetails(
       final ResultCode resultCode,
       final PasswordValidationDetailsResponseControl pvdResponse)
  {
    final PrintStream out;
    final boolean successful = (resultCode == ResultCode.SUCCESS);
    if (successful)
    {
      out = System.out;
    }
    else
    {
      out = System.err;
    }

    final List<PasswordQualityRequirementValidationResult> results =
         pvdResponse.getValidationResults();
    if (results.isEmpty())
    {
      out.println();
      out.println("The server did not return any information about whether " +
           "the proposed password satisfied the password quality " +
           "requirements.");
    }
    else
    {
      final List<PasswordQualityRequirementValidationResult> satisfiedResults =
           new ArrayList<>(results.size());
      final List<PasswordQualityRequirementValidationResult> failedResults =
           new ArrayList<>(results.size());
      for (final PasswordQualityRequirementValidationResult result : results)
      {
        if (result.requirementSatisfied())
        {
          satisfiedResults.add(result);
        }
        else
        {
          failedResults.add(result);
        }
      }

      if (! satisfiedResults.isEmpty())
      {
        out.println();
        out.println("The proposed password satisfied the following " +
             "password quality requirements:");
        for (final PasswordQualityRequirementValidationResult result :
             satisfiedResults)
        {
          out.println(resultToBulletedString(result));
        }
      }

      if (! failedResults.isEmpty())
      {
        out.println();
        out.println("The proposed password did not satisfy the following " +
             "password quality requirements:");
        for (final PasswordQualityRequirementValidationResult result :
             failedResults)
        {
          out.println(resultToBulletedString(result));
        }
      }
    }

    if (pvdResponse.missingCurrentPassword())
    {
      throw new RuntimeException("The server claims that the user's " +
           "current password is required for the password change operation. " +
           "This should only apply to self changes, and this tool should " +
           "always provide the current password for self changes. This " +
           "suggests either a bug in the server or in this tool.");
    }

    if (pvdResponse.mustChangePassword())
    {
      out.println();
      out.println("The user will be required to change their password the " +
           "next time they authenticate.");
    }

    if (pvdResponse.getSecondsUntilExpiration() != null)
    {
      out.println();
      out.println("The new password will be valid for " +
           StaticUtils.secondsToHumanReadableDuration(
                pvdResponse.getSecondsUntilExpiration()));
    }
  }



  /**
   * Retrieves a string representation of the provided password quality
   * validation result, preceded by an asterisk used as a bullet.
   *
   * @param  result  The password quality validation result to be formatted.
   *
   * @return  The string reepresentation of the provided result.
   */
  private static String resultToBulletedString(
       final PasswordQualityRequirementValidationResult result)
  {
    final StringBuilder buffer = new StringBuilder();
    buffer.append("* ");
    buffer.append(result.getPasswordRequirement().getDescription());

    if (result.getAdditionalInfo() != null)
    {
      // If there is additional info, then make sure that the description ends
      // with punctuation.
      final char lastChar = buffer.charAt(buffer.length() - 1);
      switch (lastChar)
      {
        case '.':
        case '?':
        case '!':
          buffer.append(' ');
          break;
        default:
          buffer.append(". ");
      }

      buffer.append(result.getAdditionalInfo());
    }

    return buffer.toString();
  }



  /**
   * Reads a non-empty line from standard input.
   *
   * @param  prompt  The prompt to display before reading the input.
   * @param  in      The buffered reader to use to read from standard input.
   *
   * @return  The line read from standard input.
   */
  private static String readLine(final String prompt, final BufferedReader in)
  {
    while (true)
    {
      System.out.print(prompt);

      final String line;
      try
      {
        line = in.readLine();
      }
      catch (final Exception e)
      {
        throw new RuntimeException(
             "ERROR: Unable to read from the terminal: " +
                  StaticUtils.getExceptionMessage(e),
             e);
      }

      if (line == null)
      {
        throw new RuntimeException(
             "ERROR: Unable to read from the terminal because standard input " +
                  "has been closed.");
      }

      if (line.isEmpty())
      {
        System.err.println("ERROR: The value must not be empty.");
        System.err.println();
      }
      else
      {
        return line;
      }
    }
  }



  /**
   * Reads an integer from standard input.
   *
   * @param  prompt  The prompt to display before reading the input.
   * @praam  min     The minimum allowed value.
   * @praam  max     The maximum allowed value.
   * @param  in      The buffered reader to use to read from standard input.
   *
   * @return  The integer value that was read.
   */
  private static int readInteger(final String prompt, final int min,
                                 final int max, final BufferedReader in)
  {
    while (true)
    {
      final String line = readLine(prompt, in).trim();

      final int intValue;
      try
      {
        intValue = Integer.parseInt(line);
      }
      catch (final Exception e)
      {
        System.err.println("ERROR: The value must be an integer.");
        System.err.println();
        continue;
      }

      if (intValue < min)
      {
        System.err.println(
             "ERROR: The value must be greater than or equal to " + min + '.');
        System.err.println();
        continue;
      }

      if (intValue > max)
      {
        System.err.println(
             "ERROR: The value must be less than or equal to " + max + '.');
        System.err.println();
        continue;
      }

      return intValue;
    }
  }



  /**
   * Reads a boolean value from standard input.
   *
   * @param  prompt  The prompt to display before reading the input.
   * @param  in      The buffered reader to use to read from standard input.
   *
   * @return  The boolean value that was read.
   */
  private static boolean readBoolean(final String prompt,
                                     final BufferedReader in)
  {
    while (true)
    {
      final String line  = readLine(prompt, in).trim();

      if (line.equalsIgnoreCase("yes") || line.equalsIgnoreCase("y"))
      {
        return true;
      }
      else if (line.equalsIgnoreCase("no") || line.equalsIgnoreCase("n"))
      {
        return false;
      }
      else
      {
        System.err.println(
             "ERROR: The value must be either 'yes' or 'no'.");
        System.err.println();
      }
    }
  }



  /**
   * Reads a DN from standard input.
   *
   * @param  prompt  The prompt to display before reading the input.
   * @param  in      The buffered reader to use to read from standard input.
   *
   * @return  The DN that was read.
   */
  private static DN readDN(final String prompt, final BufferedReader in)
  {
    while (true)
    {
      final String line = readLine(prompt, in).trim();

      try
      {
        return new DN(line);
      }
      catch (final Exception e)
      {
        System.err.println(
             "ERROR: Unable to parse the value as a DN: " +
                  StaticUtils.getExceptionMessage(e));
        System.err.println();
      }
    }
  }



  /**
   * Reads a password from standard input.
   *
   * @param  prompt  The prompt to display before reading the input.
   *
   * @return  The DN that was read.
   */
  private static String readPassword(final String prompt)
  {
    while (true)
    {
      System.out.print(prompt);

      final char[] passwordChars;
      try
      {
        passwordChars = PasswordReader.readPasswordChars();
      }
      catch (final Exception e)
      {
        throw new RuntimeException(
             "ERROR: Unable to read the password: " +
                  StaticUtils.getExceptionMessage(e),
             e);
      }

      if (passwordChars.length == 0)
      {
        System.err.println("ERROR: The password must not be empty.");
        System.err.println();
        continue;
      }

      return new String(passwordChars);
    }
  }
}
