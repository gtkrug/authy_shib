<%@ page import="edu.internet2.middleware.shibboleth.idp.authn.LoginContext" %>
<%@ page import="edu.internet2.middleware.shibboleth.idp.authn.LoginHandler" %>
<%@ page import="edu.internet2.middleware.shibboleth.idp.session.*" %>
<%@ page import="edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper" %>
<%@ page import="org.opensaml.saml2.metadata.*" %>

<html>
  <head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Shibboleth Identity Provider - Authy Authentication</title>
    <link rel="stylesheet" type="text/css" href="<%= request.getContextPath()%>/login.css"/>
    <link rel="stylesheet" href="flags.authy.css">
    <link rel="stylesheet" href="form.authy.css">
  </head>

  <body id="homepage">
    <img src="<%= request.getContextPath()%>/images/logo.jpg" alt="Shibboleth Logo"/>
    <h1>Duo Authentication</h1>

    <p>This second-factor authentication page is an example and should be customized.  Refer to the 
       <a href="https://wiki.shibboleth.net/confluence/display/SHIB2/IdPAuthUserPassLoginPage" target="_blank"> documentation</a>.
    </p>
     <div class="content">
      <form>
       <h3>Two-Factor Verification</h3>
        Token: <input id="authy-token"  type="text" value=""/>
        <br/>
        <a href="#" id="authy-help">help</a>
      </form>
      <script src="form.authy.js"></script>
     </div>
  </body>
</html>
