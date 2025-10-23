package org.keycloak_rsa.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import static org.keycloak_rsa.authenticator.Const.*;

/**
 * Keycloak does not persist Authenticator instances between calling {@link #authenticate(AuthenticationFlowContext)}
 * and {@link #action(AuthenticationFlowContext)}, and the provided context object is also different between the two
 * calls.
 */
public class RSAAuthenticator implements org.keycloak.authentication.Authenticator {

    private static final Logger sLogger = Logger.getLogger(RSAAuthenticator.class);

    @Override
    public void authenticate(final AuthenticationFlowContext context) {
        /*
         *  Enable the empty constructor to use environment variables
         *  configuration = new Configuration();
         */
        final Configuration configuration = new Configuration(context.getAuthenticatorConfig().getConfig());
        final Boolean isSharedUsername = configuration.getSharedUsername();

        // Create login form
        final Response challenge = context.form()
            .setAttribute(FORM_OTP_MESSAGE, DEFAULT_OTP_MESSAGE)
            .setAttribute(FORM_USERNAME_MESSAGE, DEFAULT_USERNAME_MESSAGE)
            .setAttribute(FORM_SHARED_USERNAME, isSharedUsername.toString())
            .createForm(FORM_FILE_NAME);
        context.challenge(challenge);
    }

    /**
     * This function will be called if the user submitted the OTP form
     *
     * @param context AuthenticationFlowContext
     */
    @Override
    public void action(final AuthenticationFlowContext context) {
        final MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.resetFlow();
            return;
        }

        final Configuration config = new Configuration(context.getAuthenticatorConfig().getConfig());
        final Endpoint endpoint = new Endpoint(config);
        final Boolean sharedUsername = config.getSharedUsername();

        // Get data from form
        final String otp = formData.getFirst(FORM_RSA_OTP);
        final String rsaUsername = formData.getFirst(FORM_RSA_USERNAME);

        final String currentUserName;
        if (!sharedUsername) {
            currentUserName = rsaUsername;
        } else {
            final UserModel user = context.getUser();
            currentUserName = user.getUsername();
        }

        if (otp == null || otp.isEmpty()) {
            final JsonObject error = Json.createObjectBuilder()
                .add("error", "missing_parameter")
                .add("error_description", "Missing parameter: rsa_token")
                .build();
            final Response challengeResponse = Response
                .status(Response.Status.UNAUTHORIZED)
                .entity(error)
                .build();
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        if (currentUserName == null || currentUserName.isEmpty()) {
            final JsonObject error = Json.createObjectBuilder()
                .add("error", "missing_parameter")
                .add("error_description", "Missing parameter: username")
                .build();
            final Response challengeResponse = Response
                .status(Response.Status.UNAUTHORIZED)
                .entity(error)
                .build();
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        if (!validateResponse(config, endpoint, currentUserName, otp)) {
            final LoginFormsProvider form = context.form()
                .setAttribute(FORM_OTP_MESSAGE, DEFAULT_OTP_MESSAGE)
                .setAttribute(FORM_USERNAME_MESSAGE, DEFAULT_USERNAME_MESSAGE)
                .setAttribute(FORM_SHARED_USERNAME, sharedUsername.toString());
            form.setError("Authentication failed.");

            final Response challenge = form.createForm(FORM_FILE_NAME);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }
        context.success();
    }

    /**
     * Check if authentication is successful
     *
     * @return true if authentication was successful, else false
     */
    private boolean validateResponse(
        final Configuration config,
        final Endpoint endpoint,
        final String user,
        final String otp) {

        final String verifyEndpoint = config.getVerifyEndpoint();
        final JsonObject params = buildPayload(config, user, otp);
        final JsonObject body = endpoint.sendRequest(verifyEndpoint, params, POST);
        try {
            final String result = body.getString(RSA_ATTEMPT_RESPONSE);

            if (result.equals(SUCCESS)) {
                return true;
            }
        } catch (final Exception e) {
            sLogger.error("RSA tokencode verification failed.");
        }
        return false;
    }

    private JsonObject buildPayload(final Configuration config, final String user, final String otp) {
        return Json.createObjectBuilder()
            .add(KEY_CLIENT_ID, config.getClientId())
            .add(SUBJECT_NAME, user)
            .add(
                SUBJECT_CREDENTIALS,
                Json.createArrayBuilder()
                    .add(
                        Json.createObjectBuilder()
                            .add(METHOD_ID, METHOD)
                            .add(
                                COLLECTED_INPUTS,
                                Json.createArrayBuilder()
                                    .add(Json.createObjectBuilder()
                                        .add(NAME, METHOD)
                                        .add(VALUE, otp)))))
            .add(
                CONTEXT,
                Json.createObjectBuilder()
                    .add(AUTH_ATTEMPT_ID_DESC, AUTH_ATTEMPT_ID)
                    .add(MESSAGE_ID_DESC, getMessageId())
                    .add(IN_RESPONSE_TO_DESC, IN_RESPONSE_TO))
            .build();
    }

    private static String getMessageId() {
        return RSAAuthenticator.class.getSimpleName();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(final KeycloakSession session, final RealmModel realm, final UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(final KeycloakSession session, final RealmModel realm, final UserModel user) {
    }

    @Override
    public void close() {
    }
}
