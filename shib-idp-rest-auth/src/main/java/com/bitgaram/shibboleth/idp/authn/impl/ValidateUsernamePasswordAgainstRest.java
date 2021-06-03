/*
* Copyright (C) 2017 Modern Language Association
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
* except in compliance with the License. You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
* 
* Unless required by applicable law or agreed to in writing, software distributed under
* the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/
package com.bitgaram.shibboleth.idp.authn.impl;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
//import java.time.Instant;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.login.LoginException;

import org.apache.commons.codec.binary.Hex;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.util.UriUtils;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import org.apache.http.util.EntityUtils;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson.JacksonFactory;
import com.google.api.client.util.GenericData;
import com.google.api.client.util.Key;

import net.shibboleth.idp.authn.AbstractUsernamePasswordCredentialValidator;
import net.shibboleth.idp.authn.AbstractCredentialValidator;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.ThreadSafeAfterInit;
import net.shibboleth.utilities.java.support.codec.StringDigester;
import net.shibboleth.utilities.java.support.codec.StringDigester.OutputFormat;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

@ThreadSafeAfterInit
public class ValidateUsernamePasswordAgainstRest extends AbstractUsernamePasswordCredentialValidator {
    
    /** MLA API key */
    private String apiKey = null;
    
    /** MLA API URL root */
    private String apiRoot = null;
    
    /** MLA API secret */
    private String apiSecret = null;
    
    /** HTTP transport used to query the MLA API endpoint */
    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    
    /** JSON factory used for interpreting response from MLA API */
    private static final JsonFactory JSON_FACTORY = new JacksonFactory();

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateUsernamePasswordAgainstRest.class);
    
    /** Represents a MLA member object as returned by the API */
    public static class MLAMemberObject extends GenericJson {
        @Key
        private List<MLAMemberObjectData> data;
        
        public List <MLAMemberObjectData> getData() {
            return this.data;
        }
    }
    
    /** Represents a data object child of the member object */
    public static class MLAMemberObjectData extends GenericJson {
        @Key
        private String id;
        
        @Key 
        private MLAMemberObjectDataAuthentication authentication;
        
        public MLAMemberObjectDataAuthentication getAuthentication() {
            return this.authentication;
        }
        
        public String getId() {
            return this.id;
        }
    }
    
    /** Represents an authentication object child of the data object */
    public static class MLAMemberObjectDataAuthentication extends GenericJson {
        @Key
        private String username;
        
        @Key
        private String password;
        
        @Key
        private String membership_status;
        
        public String getUsername() {
            return this.username;
        }
        
        public String getPassword() {
            return this.password;
        }
        
        public String getMembership_status() {
            return this.membership_status;
        }
    }
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
    }

    /** {@inheritDoc} */
    @Override
    @Nullable protected Subject doValidate(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext,
            @Nonnull final UsernamePasswordContext usernamePasswordContext,
            @Nullable final WarningHandler warningHandler,
            @Nullable final ErrorHandler errorHandler) throws Exception {{
        
        log.debug("{} Attempting to authenticate user {}", getLogPrefix(), usernamePasswordContext.getUsername());
        
            final String username = usernamePasswordContext.getTransformedUsername();
            final String password = usernamePasswordContext.getPassword();
            StringBuilder urlBuilder = new StringBuilder().
                    append("http://rest:4000/check/").
                    append(username).
                    append("/").
                    append(password);
            
            log.debug("{} MLA query URL is {}", getLogPrefix(), urlBuilder.toString());
            
            // Query the MLA API
             HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory(
                    new HttpRequestInitializer() {
                         @Override
                         public void initialize(HttpRequest request) {
                             /* Set default parser as a JSON parser to make casting to class instance easier */
                            request.setParser(new JsonObjectParser(JSON_FACTORY));
                         }
                    });
            HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(urlBuilder.toString()));
            HttpResponse response = request.execute();

            if (response.getStatusCode() == 404) {
                log.info("{} Login by '{}' failed", getLogPrefix(), username);
                final LoginException e = new LoginException(AuthnEventIds.INVALID_CREDENTIALS); 
                if(errorHandler != null){
                    errorHandler.handleError(profileRequestContext, authenticationContext, e, AuthnEventIds.INVALID_CREDENTIALS);
                }
                throw e;
            } else {
                log.info("{} Login by '{}' succeeded", getLogPrefix(), username);
                return populateSubject(new Subject(), usernamePasswordContext);
            }
            
    }
}
    
    /**
     * Set the MLA API key
     * 
     *  @param key key to set
     */
    public void setApiKey(@Nullable final String key) {
        this.apiKey = key;
    }
    
    /**
     * Set the MLA API root URL
     * 
     *  @param url API url to set
     */
    public void setApiRoot(@Nullable final String url) {
        this.apiRoot = url;
    }
    
    /**
     * Set the MLA API secret
     * 
     *  @param secret API secret to set
     */
    public void setApiSecret(@Nullable final String secret) {
        this.apiSecret = secret;
    }
}
