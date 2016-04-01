package org.jivesoftware.openfire.plugin.sasl;

/**
 * Validator of OAUTH Bearer tokens.
 *
 * A class that implements this interface must be thread-safe and handle multiple simultaneous requests.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public interface BearerTokenValidator
{
    ValidationResult validate( String auth, String host, String port, String mthd, String path, String post, String qs );
}
