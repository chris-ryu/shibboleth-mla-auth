package org.mla.cbox.shibboleth.idp.authn.impl;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

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
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson.JacksonFactory;
import com.google.api.client.util.Key;

import net.shibboleth.idp.authn.AbstractUsernamePasswordValidationAction;
import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;

/**
 * An action that checks for a {@link UsernamePasswordContext} and directly produces an
 * {@link net.shibboleth.idp.authn.AuthenticationResult} based on that identity by authenticating 
 * against the MLA REST API.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#AUTHN_EXCEPTION}
 * @event {@link AuthnEventIds#INVALID_CREDENTIALS}
 * @pre <pre>
 * ProfileRequestContext.getSubcontext(AuthenticationContext.class).getAttemptedFlow() != null
 * </pre>
 * @post If AuthenticationContext.getSubcontext(UsernamePasswordContext.class) != null, then an
 *       {@link net.shibboleth.idp.authn.AuthenticationResult} is saved to the {@link AuthenticationContext} on a
 *       successful login. On a failed login, the
 *       {@link AbstractValidationAction#handleError(ProfileRequestContext, AuthenticationContext, String, String)}
 *       method is called.
 */
public class ValidateUsernamePasswordAgainstMlaRest extends AbstractUsernamePasswordValidationAction {
    
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
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateUsernamePasswordAgainstMlaRest.class);
    
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
        private MLAMemberObjectDataAuthentication authentication;
        
        public MLAMemberObjectDataAuthentication getAuthentication() {
        	return this.authentication;
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

    /** {@inheritDoc} */
    @Override protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        
        log.debug("{} Attempting to authenticate user {}", getLogPrefix(), getUsernamePasswordContext() .getUsername());
        
        try {
            
            // Construct the URL composed of the API root, members method with id value equal
            //  to the username entered in the login form, the API key, and time stamp.
            StringBuilder urlBuilder = new StringBuilder().
            		append(this.apiRoot).
            		append("members/").
            		append(getUsernamePasswordContext().getUsername()).
            		append("?").
            		append("key=").
            		append(this.apiKey).
            		append("&timestamp=").
            		append(String.valueOf(Instant.now().getEpochSecond()));
            
            // The signature is created by prepending the GET method with a '&' separator to the
            //  URL and then computing the SHA256 HMAC hash using the key.
            //
            StringBuilder baseStringBuilder = new StringBuilder().
            		append("GET").
            		append("&").
            		append(UriUtils.encode(urlBuilder.toString(), "UTF-8"));
            
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(this.apiSecret.getBytes("UTF-8"), "HmacSHA256");
            sha256_HMAC.init(secretKey);
            String signature = Hex.encodeHexString(sha256_HMAC.doFinal(baseStringBuilder.toString().getBytes("UTF-8")));
            
            // Append the signature to the URL.
            urlBuilder.append("&signature=").append(signature);
            
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
            
            // Parse the response and create an instance of the MLAMemberObject.
        	MLAMemberObject mlaMembership = response.parseAs(MLAMemberObject.class);
            
            List<MLAMemberObjectData> data =  mlaMembership.getData();
            
            // The data element, if present, is a list. If not present then the size of the list
            // is zero and this indicates that the username could not be found.
            if (data.size() < 1) {
            	log.info("{} User {} is not known to MLA", getLogPrefix(), getUsernamePasswordContext().getUsername());
            	handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS, AuthnEventIds.NO_CREDENTIALS);
                return;
            }
            
            // Parse out the username, password hash, and membership status.
        	String username = data.get(0).getAuthentication().getUsername();
            String passwordHash = data.get(0).getAuthentication().getPassword();
            String membershipStatus = data.get(0).getAuthentication().getMembership_status();
            
            log.debug("{} MLA returned username {}", getLogPrefix(), username);
            log.debug("{} MLA returned password hash {}", getLogPrefix(), passwordHash);
            log.debug("{} MLA returned membership status {}", getLogPrefix(), membershipStatus);
            
            // Non-active members cannot authenticate.
            if (!new String("active").equals(membershipStatus)) {
            	log.info("{} User {} does not have active status", getLogPrefix(), getUsernamePasswordContext().getUsername());
            	handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS, AuthnEventIds.NO_CREDENTIALS);
                return;
            }
            
            // Compute the bcrypt hash of the password using the salt sent by the MLA API.
            String pw_hash = BCrypt.hashpw(getUsernamePasswordContext().getPassword(), passwordHash); 
            log.debug("{} Computed hash {}", getLogPrefix(), pw_hash);
            
            // Compare the input username with the password hash returned by the MLA API.
            if(!pw_hash.equals(passwordHash)) {
            	log.info("{} Invalid password", getLogPrefix(), getUsernamePasswordContext().getUsername());
            	handleError(profileRequestContext, authenticationContext, AuthnEventIds.INVALID_CREDENTIALS, AuthnEventIds.INVALID_CREDENTIALS);
                return;
            }
            
            // Build the authentication result and proceed.
            log.info("{} Login by '{}' succeeded", getLogPrefix(), getUsernamePasswordContext().getUsername());
            buildAuthenticationResult(profileRequestContext, authenticationContext);
            ActionSupport.buildProceedEvent(profileRequestContext);
            
//        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | InterruptedException e) {
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            log.warn("{} Login by {} produced exception", getLogPrefix(), getUsernamePasswordContext().getUsername(), e);
            handleError(profileRequestContext, authenticationContext, e, AuthnEventIds.AUTHN_EXCEPTION);
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