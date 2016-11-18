/*
 * Copyright 2016 IgniteRealtime.org
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

package org.jivesoftware.openfire.acme;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.keystore.IdentityStore;
import org.jivesoftware.openfire.spi.ConnectionType;
import org.jivesoftware.util.JiveGlobals;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.exception.AcmeConflictException;
import org.shredzone.acme4j.exception.AcmeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.TimerTask;

/**
 * Created by guus on 11/13/16.
 */
public class RegistrationUpdateCheck extends TimerTask
{
    private static final Logger Log = LoggerFactory.getLogger( RegistrationUpdateCheck.class );

    @Override
    public void run()
    {
        Log.info( "Checking for update... " );

        final KeyPair keyPair = getKeypair();
        if ( keyPair == null )
        {
            Log.error( "No key pair. Cannot run update check." );
            return;
        }

        // Start interaction with the ACME service.
        final Registration registration;
        try
        {
            registration = getRegistrationFromServer( keyPair );

            checkAgreements( registration );

            // is the registration for our domain name? Does the certificate in the registration match the one in our store?
            final Iterator<Certificate> certificates = registration.getCertificates();
            while ( certificates.hasNext() )
            {
                final Certificate certificate = certificates.next();
                final X509Certificate x509Certificate = certificate.download();
                keyPair.getPublic().
            }
            // is the certificate almost expired? ifso: update certificate (and put the updated certificate in our store)
            Log.info( "TODO do auto updates. "); // TODO;
        }
        catch ( AcmeException e )
        {
            Log.error( "An unexpected exception occurred while performing an ACME update check.", e );
        }

    }

    protected KeyPair getKeypair()
    {
        final IdentityStore identityStore = XMPPServer.getInstance().getCertificateStoreManager().getIdentityStore( ConnectionType.SOCKET_C2S );
        if ( identityStore == null ) {
            Log.error( "Unable to perform check: cannot get the identity store from which to obtain the private key." );
            return null;
        }

        Log.debug( "Iterating over identity store..." );
        final KeyStore keyStore = identityStore.getStore();

        try
        {
            for ( final Enumeration<String> certAliases = keyStore.aliases(); certAliases.hasMoreElements();)
            {
                final String alias = certAliases.nextElement();
                Log.debug( "... identity store entry alias {}: evaluating entry ...", alias );

                final X509Certificate certificate = (X509Certificate) keyStore.getCertificate( alias );
                Log.debug( "... identity store entry alias {}: has a certificate.", alias );

                final PrivateKey privKey = (PrivateKey) keyStore.getKey( alias, identityStore.getConfiguration().getPassword() );
                if ( privKey == null )
                {
                    Log.debug( "... identity store entry alias {}: has no private key. Skipping this entry.", alias );
                    continue;
                }
                Log.debug( "... identity store entry alias {}: has a private key. Using key pair from this entry.", alias );

                final PublicKey pubKey = certificate.getPublicKey();
                return new KeyPair( pubKey, privKey );
            }

            Log.warn( "Unable to identify a private key in the identity store." );
            return null;

        }
        catch ( KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e )
        {
            Log.error( "An unexpected exception occurred while trying to obtain a private key from a keystore.", e );
            return null;
        }
    }

    protected Registration getRegistrationFromServer( KeyPair keyPair ) throws AcmeException
    {
        final String acmeServer = JiveGlobals.getProperty( "tls.acme.server.uri", "acme://letsencrypt.org/staging" );
        Log.debug( "Using ACME server: {}",acmeServer );

        // Parse configuration from Jive properties.
        URI accountLocationUri = null;
        final String accountLocation = JiveGlobals.getProperty( "tls.acme.account.location.uri" );
        if ( accountLocation != null && !accountLocation.isEmpty() )
        {
            try
            {
                accountLocationUri = new URI( accountLocation );
            }
            catch ( URISyntaxException e )
            {
                Log.warn( "Unable to parse a URI from the value of property 'tls.acme.account.location.uri': '{}'.", accountLocation, e );
            }
        }
        Log.debug( "Using ACME account location: {}", accountLocationUri );

        final Session acmeSession = new Session( acmeServer, keyPair );
        Registration registration;
        if ( accountLocationUri == null )
        {
            // new registration.
            Log.info( "Creating new ACME registration." );

            try
            {
                registration = new RegistrationBuilder().create( acmeSession );
                Log.debug( "Created new ACME registrion: '{}'", registration.getLocation().toString() );
            }
            catch (AcmeConflictException ex)
            {
                Log.warn( "ACME server has a pre-existing registration for us: '{}'. Using that instead of creating a new registration.", ex.getLocation() );
                registration = Registration.bind( acmeSession, ex.getLocation() );
            }
            JiveGlobals.setProperty( "tls.acme.account.location.uri", registration.getLocation().toString() );
        }
        else
        {
            registration = Registration.bind( acmeSession, accountLocationUri );
            Log.debug( "Using ACME registration: {}", registration );
        }

        Log.debug( "Status of current ACME registration:");
        Log.debug( " - location:  {}", registration.getLocation());
        Log.debug( " - status:    {}", registration.getStatus() );
        Log.debug( " - agreement: {}", registration.getAgreement());
        for ( final URI contact : registration.getContacts() )
        {
            Log.debug( " - contact:   {}", contact );
        }
        final Iterator<Authorization> authorizations = registration.getAuthorizations();
        while ( authorizations.hasNext() )
        {
            Authorization authorization =  authorizations.next();
            Log.debug( " - authorization" );
            Log.debug( " -- location: {}", authorization.getLocation() );
            Log.debug( " -- status:   {}", authorization.getStatus() );
            Log.debug( " -- domain:   {}", authorization.getDomain() );
            Log.debug( " -- expires:  {}", authorization.getExpires() );
        }
        final Iterator<Certificate> certificates = registration.getCertificates();
        while ( certificates.hasNext() )
        {
            final Certificate certificate = certificates.next();
            Log.debug( " - certificate" );
            Log.debug( " -- location:       {}", certificate.getLocation() );
            Log.debug( " -- chain location: {}", certificate.getChainLocation() );
        }

        return registration;
    }

    protected void checkAgreements( Registration registration )
    {
        URI acmeAcceptedAgreementUri = null;
        final String acmeAcceptedAgreement = JiveGlobals.getProperty( "tls.acme.server.accepted-agreement" );
        if ( acmeAcceptedAgreement != null && !acmeAcceptedAgreement.isEmpty() )
        {
            try
            {
                acmeAcceptedAgreementUri = new URI( acmeAcceptedAgreement );
            }
            catch ( URISyntaxException e )
            {
                Log.warn( "Unable to parse a URI from the value of property 'tls.acme.server.accepted-agreement': '{}'.", acmeAcceptedAgreement, e );
            }
        }
        Log.debug( "Currently accepted ToS / Agreement: {}", acmeAcceptedAgreementUri );

        Log.debug( "Checking agreement status... ");
        if ( registration.getAgreement() != null )
        {
            if ( acmeAcceptedAgreementUri == null )
            {
                Log.info( "ACME-server provided Agreement (ToS) has not been manually been accepted. Certificate update check might fail (accept agreement in Openfire admin console)." );
            }
            else if ( !acmeAcceptedAgreementUri.equals( registration.getAgreement() ) )
            {
                Log.info( "ACME-server provided a different agreement (ToS) than the one that was previously accepted. Certificate update check might fail (accept agreement in Openfire admin console)." );
            }
        }
    }
}
