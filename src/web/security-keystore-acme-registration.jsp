<%@page import="java.util.Enumeration"%>
<%@page import="org.jivesoftware.openfire.XMPPServer"%>
<%@page import="java.security.PublicKey"%>
<%@page import="java.security.KeyPair"%>
<%@page import="java.security.cert.X509Certificate"%>
<%@page import="java.security.PrivateKey"%>
<%@page import="org.jivesoftware.openfire.keystore.IdentityStore"%>
<%@page import="java.security.KeyStore"%>
<%@page import="org.bouncycastle.asn1.x500.X500Name"%>
<%@page import="org.bouncycastle.asn1.x500.style.BCStyle"%>
<%@page import="org.bouncycastle.asn1.x509.Extension"%>
<%@page import="org.bouncycastle.asn1.x500.X500NameBuilder"%>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.Map" %>
<%@ page import="org.jivesoftware.openfire.spi.ConnectionType" %>
<%@ page import="org.jivesoftware.util.*" %>
<%@ page import="org.shredzone.acme4j.Registration" %>
<%@ page import="org.shredzone.acme4j.RegistrationBuilder" %>
<%@ page import="org.shredzone.acme4j.Session" %>
<%@ page import="java.net.URI" %>
<%@ page import="org.shredzone.acme4j.exception.AcmeConflictException" %>
<%@ taglib uri="admin" prefix="admin" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>

<%--
  ~ Copyright 2016 IgniteRealtime.org
  ~
  ~ Licensed under the Apache License, Version 2.0 (the "License");
  ~ you may not use this file except in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~     http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing, software
  ~ distributed under the License is distributed on an "AS IS" BASIS,
  ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  ~ See the License for the specific language governing permissions and
  ~ limitations under the License.
  --%>

<jsp:useBean id="webManager" class="org.jivesoftware.util.WebManager"  />
<% webManager.init(request, response, session, application, out ); %>

<% 
    String domain = XMPPServer.getInstance().getServerInfo().getXMPPDomain();

     // Get parameters:
    boolean save                    = ParamUtils.getParameter(request, "save") != null;
//    final String name               = domain;
//    final String organizationalUnit = ParamUtils.getParameter(request, "ou");
//    final String organization       = ParamUtils.getParameter(request, "o");
//    final String city               = ParamUtils.getParameter(request, "city");
//    final String state              = ParamUtils.getParameter(request, "state");
//    final String countryCode        = ParamUtils.getParameter(request, "country");
    final String connectionTypeText = ParamUtils.getParameter( request, "connectionType" );

    // CSRF
    final Map<String, String> errors = new HashMap<String, String>();
    Cookie csrfCookie = CookieUtils.getCookie(request, "csrf");
    String csrfParam = ParamUtils.getParameter(request, "csrf");

    if (save) {
        if (csrfCookie == null || csrfParam == null || !csrfCookie.getValue().equals(csrfParam)) {
            save = false;
            errors.put("csrf", "CSRF Failure!");
        }
    }
    csrfParam = StringUtils.randomString(15);
    CookieUtils.setCookie(request, response, "csrf", csrfParam, -1);
    pageContext.setAttribute("csrf", csrfParam);
    // (end of CSRF)

    try
    {
        System.out.println( "Connection Type Text: " + connectionTypeText );
        final ConnectionType connectionType = ConnectionType.valueOf( connectionTypeText );
        final IdentityStore identityStore = XMPPServer.getInstance().getCertificateStoreManager().getIdentityStore( connectionType );
        if ( identityStore == null )
        {
            errors.put( "identityStore", "Unable to get an instance." );
        }
        else
        {
            System.out.println( "Iterating over keystore..." );
            final KeyStore keyStore = identityStore.getStore();

            for ( Enumeration<String> certAliases = keyStore.aliases(); certAliases.hasMoreElements();)
            {
                String alias = certAliases.nextElement();
                System.out.println( "... iterating over alias: " + alias );

                X509Certificate certificate = (X509Certificate) keyStore.getCertificate( alias );
                System.out.println( "... has certificate" );

                final PrivateKey privKey = (PrivateKey) keyStore.getKey( alias, identityStore.getConfiguration().getPassword() );
                if ( privKey == null )
                {
                    System.out.println( "... but no private key" );
                    continue;
                }
                System.out.println( "... and private key." );
                final PublicKey pubKey = certificate.getPublicKey();
                final KeyPair keyPair = new KeyPair( pubKey, privKey );

                final String acmeServer = JiveGlobals.getProperty( "tls.acme.server.uri", "acme://letsencrypt.org/staging" );
                final String acmeAcceptedAgreement = JiveGlobals.getProperty( "tls.acme.server.accepted-agreement" );

                System.out.println( "Using ACME server: " + acmeServer );

                final Session acmeSession = new Session( acmeServer, keyPair );
                org.shredzone.acme4j.Registration registration;
                final String accountLocationUri = JiveGlobals.getProperty( "tls.acme.account.location.uri" );
                System.out.println( "Using ACME account location : " + accountLocationUri );
                if ( accountLocationUri == null )
                {
                    // new registration.
                    System.out.println( "new ACME registration." );

                    try {
                        registration = new RegistrationBuilder().create( acmeSession );
                    } catch (AcmeConflictException ex) {
                        System.out.println( "earlier registration detected, using that instead!" );
                        registration = org.shredzone.acme4j.Registration.bind( acmeSession, ex.getLocation() );
                    }
                    JiveGlobals.setProperty( "tls.acme.account.location.uri", registration.getLocation().toString() );
                }
                else
                {
                    // existing registration.
                    System.out.println( "existing ACME registration." );
                    registration = org.shredzone.acme4j.Registration.bind( acmeSession, new URI( accountLocationUri ) );
                }

                System.out.println( "Checking agreement.. ");
                if ( acmeAcceptedAgreement == null || !new URI(acmeAcceptedAgreement).equals( registration.getAgreement() ))
                {
                    pageContext.setAttribute( "acmeNeedAgreement", registration.getAgreement() );
                }

                pageContext.setAttribute( "acmeRegistration", registration );

                // Break on first cert.
                break;
            }
        }
    }
    catch (RuntimeException ex)
    {
        errors.put( "connectionType", ex.getMessage() );
    }
%>

<html>
<head>
    <title>
        <fmt:message key="ssl.signing-request.title"/>
    </title>
    <meta name="pageID" content="security-keystore-${connectionType}"/>
</head>
<body>

<% pageContext.setAttribute("errors", errors); %>
<c:forEach var="err" items="${errors}">
    <admin:infobox type="error">
        <c:choose>
            <c:when test="${err.key eq 'organizationalUnit'}">
                <fmt:message key="ssl.signing-request.enter_ou" />
            </c:when>
            <c:when test="${err.key eq 'organization'}">
                <fmt:message key="ssl.signing-request.enter_o" />
            </c:when>
            <c:when test="${err.key eq 'city'}">
                <fmt:message key="ssl.signing-request.enter_city" />
            </c:when>
            <c:when test="${err.key eq 'state'}">
                <fmt:message key="ssl.signing-request.enter_state" />
            </c:when>
            <c:when test="${err.key eq 'countryCode'}">
                <fmt:message key="ssl.signing-request.enter_country" />
            </c:when>
            <c:otherwise>
                <c:out value="${err.key}"/>
                <c:if test="${not empty err.value}">
                    <fmt:message key="admin.error"/>: <c:out value="${err.value}"/>
                </c:if>
            </c:otherwise>
        </c:choose>
    </admin:infobox>
</c:forEach>

<p>
    Use this page to create or modify a registration with the ACME provider.
</p>

<admin:contentBox title="Registration Details">

    <p>The registration with the ACME provider.</p>

    <table class="jive-table" cellpadding="0" cellspacing="0" border="0" width="100%">
        <tbody>
            <tr>
                <th>Location (URI)</th>
                <td><c:out value="${acmeRegistration.location}"/></td>
            </tr>
            <tr>
                <th>Status</th>
                <td><c:out value="${acmeRegistration.status}"/></td>
            </tr>

            <c:choose>
                <c:when test="${not empty acmeNeedAgreement}">
                    <tr>
                        <th>Agreement needed</th>
                        <td><c:out value="${acmeNeedAgreement}"/></td>
                    </tr>
                </c:when>
                <c:when test="${not empty acmeRegistration.agreement}">
                    <tr>
                        <th>Previously accepted Agreement</th>
                        <td><c:out value="${acmeRegistration.agreement}"/></td>
                    </tr>
                </c:when>
            </c:choose>
        </tbody>
    </table>

</admin:contentBox>
</body>
</html>
