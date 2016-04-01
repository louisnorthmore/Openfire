package org.jivesoftware.openfire.plugin.sasl;

/**
 * Result of a validation.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class ValidationResult
{
    private final String value;
    private final boolean valid;

    public static ValidationResult success( String authorizedUser )
    {
        return new ValidationResult( true, authorizedUser );
    }

    // errorMessage should be one of: http://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#extensions-error
    public static ValidationResult failure( String errorMessage )
    {
        return new ValidationResult( false, errorMessage );
    }

    private ValidationResult( boolean valid, String value )
    {
        this.value = value;
        this.valid = valid;
    }

    public boolean isValid()
    {
        return valid;
    }

    public String getAuthorizedUser()
    {
        if ( !valid )
        {
            throw new IllegalStateException( "Validation was not successful." );
        }
        return value;
    }

    public String getErrorMessage()
    {
        if ( valid )
        {
            throw new IllegalStateException( "Validation was successful." );
        }
        return value;
    }
}
