<%@ page import="org.jivesoftware.util.*,
                 java.util.*,
                 java.net.URLEncoder"
         errorPage="error.jsp"
%>
<%@ page import="org.jivesoftware.openfire.muc.MultiUserChatService" %>
<%@ page import="org.xmpp.packet.JID" %>
<%@ page import="org.jivesoftware.openfire.XMPPServer" %>
<%@ page import="org.jivesoftware.openfire.pubsub.PubSubModule" %>

<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<jsp:useBean id="webManager" class="org.jivesoftware.util.WebManager"  />
<% webManager.init(request, response, session, application, out );

    final PubSubModule pubSubModule = XMPPServer.getInstance().getPubSubModule();
    pageContext.setAttribute( "pubSubModule", pubSubModule );

%>

<html>
<head>
    <title><fmt:message key="pubsub.summary.title"/></title>
    <%--<meta name="pageID" content="sidebar-pubsub-admin"/>--%>
</head>
<body>

<p>
    <fmt:message key="pubsub.summary.info" />
</p>
<p>
    <b>Service Address</b>: <c:out value="${pubSubModule.address}"/> <br/>
</p>
<h2>Nodes</h2>
    <c:forEach var="node" items="${pubSubModule.nodes}">
        <c:if test="${not empty node.nodeID}">
    <table cellpadding="3" cellspacing="0" border="1">
        <tr>
            <th>NodeId</th><td><c:out value="${node.nodeID}"/></td>
        </tr>
        <tr>
            <th>Creator</th><td><c:out value="${node.creator}"/></td>
        </tr>
        <tr>
            <th>Creation date</th><td><c:out value="${node.creationDate}"/></td>
        </tr>
        <tr>
            <th>Description</th><td><c:out value="${node.description}"/></td>
        </tr>
        <tr>
            <th>Language</th><td><c:out value="${node.language}"/></td>
        </tr>
        <tr>
            <th>Modification&nbsp;date</th><td><c:out value="${node.modificationDate}"/></td>
        </tr>
        <tr>
            <th>Access&nbsp;model</th><td><c:out value="${node.accessModel.name}"/> (auth required: <c:out value="${node.accessModel.authorizationRequired}"/>)</td>
        </tr>
        <tr>
            <th>Publisher&nbsp;model</th><td><c:out value="${node.publisherModel.name}"/></td>
        </tr>
        <tr>
            <th>Payload&nbsp;type</th><td><c:out value="${node.payloadType}"/></td>
        </tr>
        <tr>
            <th>Payload&nbsp;delivered?</th><td><c:out value="${node.payloadDelivered}"/></td>
        </tr>
        <tr>
            <th>Owners</th>
            <td>
                <c:forEach var="owner" items="${node.owners}">
                    <c:out value="${owner}"/><br/>
                </c:forEach>
            </td>
        </tr>
        <tr>
            <th>Publisher</th>
            <td>
                <c:forEach var="publisher" items="${node.publishers}">
                    <c:out value="${publisher}"/><br/>
                </c:forEach>
            </td>
        </tr>
        <tr>
            <th>Contacts</th>
            <td>
                <c:forEach var="contact" items="${node.contacts}">
                    <c:out value="${contact}"/><br/>
                </c:forEach>
            </td>
        </tr>
        <tr>
            <th>Subscriptions</th>
            <td>
                <c:forEach var="subscription" items="${node.allSubscriptions}">
                    <c:out value="${subscription.ID}"/> c:out value="${subscription.JID}"/> c:out value="${subscription.type}"/><br/>
                </c:forEach>
            </td>
        </tr>
        <tr>
            <th>Last&nbsp;Published&nbsp;Item</th><td><c:out value="${node.lastPublishedItem.payloadXML}"/></td>
        </tr>
    </table>
        <br/>
        </c:if>
    </c:forEach>

</body>
</html>
