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

import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerFactoryBean;

/**
 * Factory bean for {@link AuthyTwoFactorLoginHandler}s.
 */
public class AuthyTwoFactorLoginHandlerFactoryBean extends AbstractLoginHandlerFactoryBean{

    /** URL to authentication servlet. */
    private String authenticationServletURL;

    /**
     * Gets the URL to authentication servlet.
     * 
     * @return URL to authentication servlet
     */
    public String getAuthenticationServletURL() {
        return authenticationServletURL;
    }

    /**
     * Sets URL to authentication servlet.
     * 
     * @param url URL to authentication servlet
     */
    public void setAuthenticationServletURL(String url) {
        authenticationServletURL = url;
    }

    // Authy attributes
    private String name    = null;
    private String apikey  = null;
    private String apihost = null;

    // Authy attribute getter/setters
    public String getAuthyApiURL(){
        return apihost;
    }
    public void setAuthyApiURL(String s){
        apihost = s;
    }
    public String getApiKey(){
        return apikey;
    }
    public void setApiKey(String s){
        apikey = s;
    }
    public String getName(){
        return name;
    }
    public void setName(String s){
        name = s;
    }

    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        AuthyTwoFactorLoginHandler handler = new AuthyTwoFactorLoginHandler(authenticationServletURL, apikey, name, apihost);

        populateHandler(handler);

        return handler;
    }

    /** {@inheritDoc} */
    public Class getObjectType() {
        return AuthyTwoFactorLoginHandler.class;
    }
}
