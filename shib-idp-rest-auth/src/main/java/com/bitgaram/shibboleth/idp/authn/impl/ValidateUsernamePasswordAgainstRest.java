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
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import javax.security.auth.login.LoginException;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import javax.security.auth.Subject;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.util.UriComponentsBuilder;

import net.shibboleth.idp.authn.AbstractUsernamePasswordCredentialValidator;
import net.shibboleth.idp.authn.AbstractCredentialValidator;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.annotation.constraint.NonnullElements;
import net.shibboleth.shared.annotation.constraint.ThreadSafeAfterInit;
import net.shibboleth.shared.codec.StringDigester;
import net.shibboleth.shared.codec.StringDigester.OutputFormat;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.component.ComponentSupport;
import net.shibboleth.shared.logic.Constraint;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;

import net.shibboleth.idp.authn.principal.UsernamePrincipal;

@ThreadSafeAfterInit
public class ValidateUsernamePasswordAgainstRest extends AbstractUsernamePasswordCredentialValidator {
    
    /** MLA API key */
    private String apiKey = null;
    
    /** MLA API secret */
    private String apiSecret = null;
    
    /** MLA API URL root - default to http://rest:4000/check but can be configured */
    private String apiRoot = "http://rest:4000/check";
    
    /** Connection timeout in seconds */
    private int connectionTimeout = 10;
    
    /** Number of retry attempts for transient failures */
    private int retryAttempts = 2;
    
    /** HTTP transport used to query the MLA API endpoint with configurable timeout */
    private HttpClient httpClient;
    
    /** JSON factory used for interpreting response from MLA API */
    private static final Gson GSON = new Gson();

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateUsernamePasswordAgainstRest.class);
    
    /** Represents a MLA member object as returned by the API */
    public static class MLAMemberObject {
        private List<MLAMemberObjectData> data;
        
        public List <MLAMemberObjectData> getData() {
            return this.data;
        }
    }
    
    /** Represents a data object child of the member object */
    public static class MLAMemberObjectData {
        private String id;
        private MLAMemberObjectDataAuthentication authentication;
        
        public MLAMemberObjectDataAuthentication getAuthentication() {
            return this.authentication;
        }
        
        public String getId() {
            return this.id;
        }
    }
    
    /** Represents an authentication object child of the data object */
    public static class MLAMemberObjectDataAuthentication {
        private String username;
        private String password;
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
        
        // Initialize HTTP client with configured timeout and better defaults for Kubernetes environments
        httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(connectionTimeout))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
            
        log.info("{} Initialized with apiRoot: {}, connectionTimeout: {}s, retryAttempts: {}", 
            getLogPrefix(), apiRoot, connectionTimeout, retryAttempts);
            
        // Test connection to REST API endpoint during initialization
        if (!testConnection()) {
            log.warn("{} CONNECTIVITY TEST FAILED: Could not connect to REST API endpoint: {}. Authentication will likely fail!", 
                getLogPrefix(), apiRoot);
            
            // Run network diagnostics to help identify the issue
            runNetworkDiagnostics();
        }
    }
    
    /**
     * Test connection to the REST API endpoint
     * 
     * @return true if connection successful, false otherwise
     */
    private boolean testConnection() {
        try {
            log.debug("{} Testing connection to REST API endpoint: {}", getLogPrefix(), apiRoot);
            
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(apiRoot))
                .GET()  // Changed from .method("HEAD", HttpRequest.BodyPublishers.noBody())
                .timeout(Duration.ofSeconds(connectionTimeout))
                .build();
                
            HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                log.info("{} Successfully connected to REST API endpoint: {}", getLogPrefix(), apiRoot);
                return true;
            } else {
                log.warn("{} REST API endpoint test returned status code: {}", getLogPrefix(), response.statusCode());
                return false;
            }
        } catch (Exception e) {
            log.warn("{} Failed to connect to REST API endpoint: {} - Error: {}", 
                getLogPrefix(), apiRoot, e.toString());
            return false;
        }
    }

    /** {@inheritDoc} */
    @Override
    @Nullable protected Subject doValidate(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext,
            @Nonnull final UsernamePasswordContext usernamePasswordContext,
            @Nullable final WarningHandler warningHandler,
            @Nullable final ErrorHandler errorHandler) throws Exception {
        
        this.log.debug("{} Attempting to authenticate user {}", getLogPrefix(), usernamePasswordContext.getUsername());
        String username = usernamePasswordContext.getTransformedUsername();
        String password = URLEncoder.encode(usernamePasswordContext.getPassword(), "UTF-8");
        String authPath = "http://rest:4000/auth"; 
        String url = String.format("%s/%s/%s", authPath, username, password);
        this.log.debug("{} MLA query URL is {}", getLogPrefix(), url);
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .GET()
            .timeout(Duration.ofSeconds(connectionTimeout))
            .build();
        
        // Add retry logic for transient errors
        Exception lastException = null;
        for (int attempt = 0; attempt <= retryAttempts; attempt++) {
            try {
                if (attempt > 0) {
                    log.info("{} Retry attempt {} of {} for user '{}'", 
                        getLogPrefix(), attempt, retryAttempts, username);
                    // Add a small delay before retrying
                    Thread.sleep(1000 * attempt);
                }
                
                log.debug("{} Sending HTTP request to REST endpoint", getLogPrefix());
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                log.debug("{} Received response with status code: {}", getLogPrefix(), response.statusCode());
                
                if (response.statusCode() == 404) {
                    this.log.info("{} Login by '{}' failed - user not found or invalid credentials", getLogPrefix(), username);
                    LoginException e = new LoginException("InvalidCredentials");
                    if (errorHandler != null) {
                        errorHandler.handleError(profileRequestContext, authenticationContext, e, AuthnEventIds.INVALID_CREDENTIALS);
                    }
                    throw e;
                } else if (response.statusCode() != 200) {
                    // Handle other non-200 status codes
                    String errorMsg = String.format("REST service returned status code %d", response.statusCode());
                    log.warn("{} {}", getLogPrefix(), errorMsg);
                    
                    if (isTransientError(response.statusCode()) && attempt < retryAttempts) {
                        // For transient errors, continue to the next retry attempt
                        lastException = new LoginException(errorMsg);
                        continue;
                    } else {
                        // For non-transient errors or when we've exhausted retries
                        LoginException e = new LoginException(errorMsg);
                        handleAuthenticationError(profileRequestContext, authenticationContext, e, 
                            AuthnEventIds.INVALID_CREDENTIALS, errorHandler);
                        throw e;
                    }
                }
                
                // Check response body for any error indicators
                String responseBody = response.body();
                log.debug("{} Response body: {}", getLogPrefix(), responseBody);
                
                if (responseBody == null || responseBody.isEmpty()) {
                    log.warn("{} Empty response received from REST service", getLogPrefix());
                    LoginException e = new LoginException("EmptyResponse");
                    handleAuthenticationError(profileRequestContext, authenticationContext, e, 
                        AuthnEventIds.INVALID_CREDENTIALS, errorHandler);
                    throw e;
                }
                
                // Parse response and check for success
                try {
                    JsonObject jsonResponse = GSON.fromJson(responseBody, JsonObject.class);
                    if (jsonResponse.has("success") && !jsonResponse.get("success").getAsBoolean()) {
                        // Handle explicit failure response
                        String errorMsg = "Authentication failed";
                        if (jsonResponse.has("message")) {
                            errorMsg = jsonResponse.get("message").getAsString();
                        }
                        log.info("{} Login by '{}' failed: {}", getLogPrefix(), username, errorMsg);
                        LoginException e = new LoginException(errorMsg);
                        handleAuthenticationError(profileRequestContext, authenticationContext, e, 
                            AuthnEventIds.INVALID_CREDENTIALS, errorHandler);
                        throw e;
                    }
                } catch (Exception e) {
                    // JSON parsing error is not fatal if the status code was 200
                    log.warn("{} Failed to parse JSON response: {}", getLogPrefix(), e.getMessage());
                }
                
                this.log.info("{} Login by '{}' succeeded", getLogPrefix(), username);
                return this.populateSubject(new Subject(), usernamePasswordContext);
                
            } catch (java.net.SocketTimeoutException e) {
                // Timeout exception handling
                String errorMsg = String.format("Network timeout connecting to REST service: %s", e.getMessage());
                log.warn("{} {}", getLogPrefix(), errorMsg);
                lastException = e;
                
                // Run diagnostics on the first failure
                if (attempt == 0) {
                    runNetworkDiagnostics();
                }
                
                // If we have retries left, continue to the next attempt
                if (attempt < retryAttempts) {
                    continue;
                }
            } catch (java.io.IOException e) {
                // General I/O exceptions including ConnectException
                String errorMsg = String.format("Network error connecting to REST service: %s", e.getMessage());
                log.warn("{} {}", getLogPrefix(), errorMsg);
                lastException = e;
                
                // Run diagnostics on the first failure
                if (attempt == 0) {
                    runNetworkDiagnostics();
                }
                
                // If we have retries left, continue to the next attempt
                if (attempt < retryAttempts) {
                    continue;
                }
            } catch (InterruptedException e) {
                // Interrupted during retry sleep
                Thread.currentThread().interrupt();
                log.warn("{} Authentication retry interrupted", getLogPrefix());
                lastException = e;
                break;
            }
        }
        
        // If we get here, all retry attempts have failed
        if (lastException != null) {
            log.error("{} Authentication failed after {} retry attempts", getLogPrefix(), retryAttempts);
            LoginException loginException = new LoginException("Authentication failed due to service unavailability");
            loginException.initCause(lastException);
            handleAuthenticationError(profileRequestContext, authenticationContext, loginException, 
                AuthnEventIds.INVALID_CREDENTIALS, errorHandler);
            throw loginException;
        }
        
        // This should never happen, but just in case
        LoginException e = new LoginException("Authentication failed under unexpected circumstances");
        handleAuthenticationError(profileRequestContext, authenticationContext, e, 
            AuthnEventIds.INVALID_CREDENTIALS, errorHandler);
        throw e;
    }
    
    /**
     * Determine if an HTTP status code represents a transient error that should be retried
     * 
     * @param statusCode the HTTP status code
     * @return true if the error is transient and should be retried
     */
    private boolean isTransientError(int statusCode) {
        // 5xx errors and certain 4xx errors are potentially transient
        return statusCode >= 500 || statusCode == 429 || statusCode == 408;
    }
    
    /**
     * Helper method to handle authentication errors
     * 
     * @param profileRequestContext the profile request context
     * @param authenticationContext the authentication context
     * @param exception the exception that occurred
     * @param eventId the event ID to use
     * @param errorHandler the error handler to call
     * @throws Exception if the error handler throws an exception
     */
    private void handleAuthenticationError(
            @Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext,
            @Nonnull final Exception exception,
            @Nonnull final String eventId,
            @Nullable final ErrorHandler errorHandler) throws Exception {
        if (errorHandler != null) {
            errorHandler.handleError(profileRequestContext, authenticationContext, exception, eventId);
        }
        throw exception;
    }
    
    /**
     * Set the MLA API key
     * 
     *  @param key key to set
     */
    public void setApiKey(@Nullable final String key) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        this.apiKey = key;
    }
    
    /**
     * Set the MLA API root URL
     * 
     *  @param url API url to set
     */
    public void setApiRoot(@Nullable final String url) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        if (url != null && !url.isEmpty()) {
            this.apiRoot = url;
        }
    }
    
    /**
     * Set the MLA API secret
     * 
     *  @param secret API secret to set
     */
    public void setApiSecret(@Nullable final String secret) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        this.apiSecret = secret;
    }
    
    /**
     * Set the connection timeout in seconds
     * 
     * @param seconds timeout in seconds
     */
    public void setConnectionTimeout(final int seconds) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        if (seconds > 0) {
            this.connectionTimeout = seconds;
        }
    }
    
    /**
     * Set the number of retry attempts for transient failures
     * 
     * @param attempts number of retry attempts
     */
    public void setRetryAttempts(final int attempts) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        if (attempts >= 0) {
            this.retryAttempts = attempts;
        }
    }
    
    /**
     * Run network diagnostics to help identify connection issues
     */
    private void runNetworkDiagnostics() {
        try {
            URI uri = URI.create(apiRoot);
            String host = uri.getHost();
            int port = uri.getPort() > 0 ? uri.getPort() : (uri.getScheme().equals("https") ? 443 : 80);
            
            log.info("{} Running network diagnostics for {}:{}", getLogPrefix(), host, port);
            
            // Try to resolve host using DNS
            try {
                java.net.InetAddress address = java.net.InetAddress.getByName(host);
                log.info("{} DNS resolution: {} resolves to {}", getLogPrefix(), host, address.getHostAddress());
            } catch (Exception e) {
                log.warn("{} DNS resolution failed: {} - {}", getLogPrefix(), host, e.toString());
            }
            
            // Try socket connection to verify reachability
            try (java.net.Socket socket = new java.net.Socket()) {
                socket.connect(new java.net.InetSocketAddress(host, port), (int)(connectionTimeout * 1000));
                log.info("{} TCP connection: Successfully connected to {}:{}", getLogPrefix(), host, port);
            } catch (Exception e) {
                log.warn("{} TCP connection failed to {}:{} - {}", getLogPrefix(), host, port, e.toString());
                log.warn("{} IMPORTANT: Make sure the Kubernetes service 'rest' exists and is properly configured!", getLogPrefix());
                // Additional Kubernetes-specific guidance
                log.warn("{} Check that pods backing the 'rest' service are running: 'kubectl get pods -l app=rest'", getLogPrefix());
                log.warn("{} Verify service endpoints: 'kubectl get endpoints rest'", getLogPrefix());
                log.warn("{} Check if the REST service is in the same namespace as your Shibboleth pod", getLogPrefix());
            }
            
            // Run a traceroute to the host
            runTraceroute(host);
            
        } catch (Exception e) {
            log.warn("{} Failed to run network diagnostics: {}", getLogPrefix(), e.toString());
        }
    }
    
    /**
     * Run a traceroute test to the REST service host to identify routing problems
     * 
     * @param host the host to trace route to
     */
    private void runTraceroute(String host) {
        try {
            log.info("{} Attempting to trace route to host: {}", getLogPrefix(), host);
            
            // Create a process to run traceroute
            ProcessBuilder processBuilder = new ProcessBuilder();
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                processBuilder.command("tracert", "-d", "-h", "15", host);
            } else {
                processBuilder.command("traceroute", "-m", "15", host);
            }
            
            Process process = processBuilder.start();
            
            // Read the output
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                log.info("{} TRACEROUTE: {}", getLogPrefix(), line);
            }
            
            // Wait for the process to complete
            int exitCode = process.waitFor();
            log.info("{} Traceroute completed with exit code: {}", getLogPrefix(), exitCode);
            
        } catch (Exception e) {
            log.warn("{} Failed to run traceroute: {}", getLogPrefix(), e.toString());
        }
    }

    /**
     * A hook method to check the credentials from the underlying data store.
     * 
     * @param username    A non-empty username to check
     * @param password    A password to check
     * @return True iff the username/password is/are valid
     * @throws Exception if an error occurs in the validation process
     */
    protected boolean checkCredential(@Nonnull final String username, @Nonnull final String password) throws Exception {
        throw new UnsupportedOperationException("checkCredential() not supported");
    }

    public boolean supportsCredential(Class<?> credentialClass) {
        return credentialClass.equals(UsernamePasswordContext.class);
    }

    /**
     * Populate a subject before returning the result of the password validator.
     * This base implementation does nothing and is meant to be overridden by subclasses.
     * 
     * @param  subject the subject to populate
     * @param  usernamePasswordContext the username/password context
     * @return the populated subject
     */
    protected Subject populateSubject(final Subject subject, final UsernamePasswordContext usernamePasswordContext) {
        // 인증된 사용자 이름으로 UsernamePrincipal 생성하여 Subject에 추가
        subject.getPrincipals().add(new UsernamePrincipal(usernamePasswordContext.getTransformedUsername()));
        
        // 필요에 따라 추가 Principal 객체 생성 가능
        // subject.getPrincipals().add(new AuthenticationMethodPrincipal("RestAuthentication"));
        
        return subject;
    }
}
