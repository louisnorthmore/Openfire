package org.jivesoftware.openfire.plugin.sasl;

import java.util.regex.Pattern;

/**
 * Representation of a GS2-header, as specified in section 4 of RFC 5801: "Using Generic Security Service Application
 * Program Interface (GSS-API) Mechanisms in Simple Authentication and Security Layer (SASL): The GS2 Mechanism Family"
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 * @see <a href="https://tools.ietf.org/html/rfc5801">RFC 5801</a>
 */
public class GS2Header
{
    public static final Pattern CB_FLAG_PATTERN = Pattern.compile( "^((p\\=(([A-Z.a-z0-9\\-]|)+))|n|y)$" );

    /**
     * The value of the (optional) 'gs2-nonstd-flag' attribute.
     *
     * Value in ABNF: "F"
     *
     * "F" means the mechanism is not a standard GSS-API mechanism in that the RFC 2743, Section 3.1 header was missing.
     */
    private final Character nonstdFlag;

    /**
     * The value of the (non-optional) 'gs2-cb-flag' attribute.
     *
     * Value in ABNF: ("p=" cb-name) / "n" / "y"
     *
     * GS2 channel binding (CB) flag
     * "p" -> client supports and used CB
     * "n" -> client does not support CB
     * "y" -> client supports CB, thinks the server does not
     *
     * cb-name in ABNF: 1*(ALPHA / DIGIT / "." / "-")
     * See RFC 5056, Section 7.
     */
    private final String cbFlag;

    /**
     * The value of the (optional) 'gs2-authzid' attribute (expected to be null or 'F').
     *
     * Value in ABNF: "a=" saslname
     * GS2 has to transport an authzid since the GSS-API has no equivalent
     *
     * saslname in ABNF: 1*(UTF8-char-safe / "=2C" / "=3D")
     */
    private final String authzId;

    public static GS2Header parse( String value ) {
        if ( value == null || value.isEmpty() ) {
            throw new IllegalArgumentException( "Argument 'value' cannot be null or empty." );
        }

        final String[] parts = value.split( "," );
        switch( parts.length ) {
            case 2:
                return new GS2Header( null, parts[0], parts[1] );
            case 3:
                if (parts[0].length() != 1 ) {
                    throw new IllegalArgumentException( "Invalid 'gs2-nonstd-flag' value." );
                }
                return new GS2Header( parts[0].charAt( 0 ), parts[1], parts[2] );
            default:
                throw new IllegalArgumentException( "Argument 'value' must contain at least two and at most three comma characters." );
        }
    }

    // Protected instead of public as the implementation does not validate the entire GS2-header value (notably: the usage of comma's).
    protected GS2Header( Character nonstdFlag, String cbFlag, String authzId )
    {
        if ( nonstdFlag != null && nonstdFlag != 'F' ) {
            throw new IllegalArgumentException( "Argument 'nonstdFlag' must be either null or 'F' (but was: '"+nonstdFlag+"')." );
        }

        if ( cbFlag == null || cbFlag.isEmpty() ) {
            throw new IllegalArgumentException( "Argument 'cbFlag' cannot be null or empty." );
        }

        if ( !CB_FLAG_PATTERN.matcher( cbFlag ).matches() ) {
            throw new IllegalArgumentException( "Argument 'cbFlag' is not valid." );
        }

        // TODO improve on this gs2-authzid attribute value verification (the implementation below is not complete).
        if ( authzId != null && !authzId.isEmpty() && ( authzId.length() < 3 || !authzId.startsWith( "a=" ) ) ) {
            throw new IllegalArgumentException( "Argument 'authzId' is not valid." );
        }

        this.nonstdFlag = nonstdFlag;
        this.cbFlag = cbFlag;

        if (authzId == null || authzId.isEmpty() )
        {
            this.authzId = null;
        }
        else
        {
            this.authzId = authzId;
        }
    }

    /**
     * The value of the (optional) 'gs2-nonstd-flag' attribute.
     *
     * Value in ABNF: "F"
     *
     * "F" means the mechanism is not a standard GSS-API mechanism in that the RFC 2743, Section 3.1 header was missing.
     */
    public Character getNonstdFlag()
    {
        return nonstdFlag;
    }

    /**
     * The value of the (non-optional) 'gs2-cb-flag' attribute.
     *
     * Value in ABNF: ("p=" cb-name) / "n" / "y"
     *
     * GS2 channel binding (CB) flag
     * "p" -> client supports and used CB
     * "n" -> client does not support CB
     * "y" -> client supports CB, thinks the server does not
     *
     * cb-name in ABNF: 1*(ALPHA / DIGIT / "." / "-")
     * See RFC 5056, Section 7.
     */
    public String getCbFlag()
    {
        return cbFlag;
    }

    /**
     * The value of the (optional) 'gs2-authzid' attribute (expected to be null or 'F').
     *
     * Value in ABNF: "a=" saslname
     * GS2 has to transport an authzid since the GSS-API has no equivalent
     *
     * saslname in ABNF: 1*(UTF8-char-safe / "=2C" / "=3D")
     */
    public String getAuthzId()
    {
        return authzId;
    }

    /**
     * Returns the (decoded) authorization identity as provided in the 'gs2-authzid' attribute. If this attribute is not
     * set in this instance, null is returned.
     *
     * @return an authorization identity, or null.
     */
    public String getAuthorizationIdentity()
    {
        if ( authzId == null ) {
            return null;
        }

        return authzId.substring( "a=".length() ).replace( "=2C", "," ).replace( "=3D", "=" );
    }

    /**
     * Returns the name of the channel binding, or null if no channel binding was used (as indicated by the
     * 'gs2-cb-flag' attribute).
     *
     * @return the channel binding name, or null.
     */
    public String getChannelBindingName()
    {
        if ( cbFlag.startsWith( "p=" ) ) {
            return cbFlag.substring( 2 );
        }

        return null;
    }

    @Override
    public boolean equals( Object o )
    {
        if ( this == o )
        {
            return true;
        }
        if ( !( o instanceof GS2Header ) )
        {
            return false;
        }

        GS2Header gs2Header = (GS2Header) o;

        if ( nonstdFlag != null ? !nonstdFlag.equals( gs2Header.nonstdFlag ) : gs2Header.nonstdFlag != null )
        {
            return false;
        }
        if ( !cbFlag.equals( gs2Header.cbFlag ) )
        {
            return false;
        }
        return !( authzId != null ? !authzId.equals( gs2Header.authzId ) : gs2Header.authzId != null );

    }

    @Override
    public int hashCode()
    {
        int result = nonstdFlag != null ? nonstdFlag.hashCode() : 0;
        result = 31 * result + cbFlag.hashCode();
        result = 31 * result + ( authzId != null ? authzId.hashCode() : 0 );
        return result;
    }
}
