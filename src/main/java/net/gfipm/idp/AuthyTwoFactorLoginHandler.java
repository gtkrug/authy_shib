/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
/* Copyright 2014 Georgia Tech Research Institute
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

package net.gfipm.idp;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.provider.AbstractLoginHandler;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

/**
 * Login handler to authenticate a username and password against a JAAS source,
 * then authenticate with Authy for a second factor. 
 * Based on Duo's Handler, which was based on the Shib UsernamePasswordLoginHandler.
 * 
 */
public class AuthyTwoFactorLoginHandler extends AbstractLoginHandler {

     /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AuthyTwoFactorLoginHandler.class);

    /** The context-relative path of the servlet used to perform authentication. */
    private String authenticationServletPath;

    // Authy attributes.
    private String apikey;
    private String apihost;
    private String name;

    /**
     * Constructor.
     * 
     * @param servletPath context-relative path to the authentication servlet, may start with "/"
     * @param apikeyIn  Authy API Key
     * @param nameIn    Authy Application Name
     * @param apiHostIn Authy Host
     */
    public AuthyTwoFactorLoginHandler(String servletPath, String apiKeyIn, String nameIn, String apiHostIn) {
        super();
        setSupportsPassive(false);
        setSupportsForceAuthentication(true);
        authenticationServletPath = servletPath;
        apikey  = apiKeyIn;
        name    = nameIn;
        apihost = apiHostIn;
    }

    /** {@inheritDoc} */
    public void login(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse) {
        // forward control to the servlet.
        try {
            httpRequest.getSession().setAttribute(AuthyTwoFactorLoginServlet.API_KEY,  apikey);
            httpRequest.getSession().setAttribute(AuthyTwoFactorLoginServlet.API_HOST, apihost);
            httpRequest.getSession().setAttribute(AuthyTwoFactorLoginServlet.API_NAME, name);

            String authnServletUrl = HttpServletHelper.getContextRelativeUrl(httpRequest, authenticationServletPath).buildURL();
            log.debug("Redirecting to {}", authnServletUrl);
            httpResponse.sendRedirect(authnServletUrl);
            return;
        } catch (IOException ex) {
            log.error("Unable to redirect to authentication servlet.", ex);
        }

    }
}
