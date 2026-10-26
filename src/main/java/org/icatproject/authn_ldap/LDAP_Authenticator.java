package org.icatproject.authn_ldap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;
import java.util.Hashtable;

import jakarta.annotation.PostConstruct;
import jakarta.ejb.Stateless;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonValue;
import jakarta.json.stream.JsonGenerator;
import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.icatproject.authentication.AuthnException;
import org.icatproject.utils.AddressChecker;
import org.icatproject.utils.AddressCheckerException;
import org.icatproject.utils.CheckedProperties;
import org.icatproject.utils.CheckedProperties.CheckedPropertyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

@Path("/")
@Stateless
public class LDAP_Authenticator {

	public enum Case {
		UPPER, LOWER
	}

	private static final Logger logger = LoggerFactory.getLogger(LDAP_Authenticator.class);
	private static final Marker fatal = MarkerFactory.getMarker("FATAL");
	private static final String AUTHENTICATION_FAILED = "The username and password do not match ";

	private String securityPrincipal;
	private String providerUrl;
	private AddressChecker addressChecker;

	private String mechanism;
	private Hashtable<Object, Object> authEnv;
	private String ldapBase;
	private String ldapFilter;
	private String ldapAttribute;
	private Case userNameCase;
	private String presearchSecurityPrincipal;
	private String presearchSecurityCredentials;

	@PostConstruct
	private void init() {

		CheckedProperties props = new CheckedProperties();
		try {
			props.loadFromResource("run.properties");

			if (props.has("ip")) {
				String authips = props.getString("ip");
				try {
					addressChecker = new AddressChecker(authips);
				} catch (Exception e) {
					String msg = "Problem creating AddressChecker with information from run.properties."
							+ e.getMessage();
					logger.error(fatal, msg);
					throw new IllegalStateException(msg);
				}
			}

			this.providerUrl = props.getString("provider_url");

			this.securityPrincipal = props.getString("security_principal");
			if (securityPrincipal.indexOf('%') < 0) {
				String msg = "security_principal value must include a % to be substituted by the user name ";
				logger.error(fatal, msg);
				throw new IllegalStateException(msg);
			}

			authEnv = new Hashtable<>();
			authEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
			authEnv.put(Context.PROVIDER_URL, providerUrl);
			authEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
			if (props.has("context.props")) {
				for (String prop : props.getString("context.props").trim().split("\\s+")) {
					String value = props.getString("context.props." + prop);
					authEnv.put(prop, value);
				}
			}

			if (props.has("ldap.base") || props.has("ldap.filter") || props.has("ldap.attribute")) {
				ldapBase = props.getString("ldap.base");
				ldapFilter = props.getString("ldap.filter");
				ldapAttribute = props.getString("ldap.attribute");
			}

			if (props.has("presearch.security_principal")) {
				if (ldapBase == null) {
					String msg = "presearch.security_principal requires ldap.base, ldap.filter "
							+ "and ldap.attribute to also be set";
					logger.error(fatal, msg);
					throw new IllegalStateException(msg);
				}
				presearchSecurityPrincipal = props.getString("presearch.security_principal");
				presearchSecurityCredentials = props.getString("presearch.security_credentials");
			}

			if (props.has("case")) {
				String nameCase = props.getString("case");
				if (nameCase.equals("upper")) {
					userNameCase = Case.UPPER;
				} else if (nameCase.equals("lower")) {
					userNameCase = Case.LOWER;
				} else {
					String msg = "The \"case\" property, if present, must be \"upper\" or \"lower\"";
					logger.error(fatal, msg);
					throw new IllegalStateException(msg);
				}
			}

			if (props.has("mechanism")) {
				mechanism = props.getString("mechanism");
			}
		} catch (CheckedPropertyException e) {
			logger.error(fatal, e.getMessage());
			throw new IllegalStateException(e.getMessage());
		}

		logger.debug("Initialised LDAP_Authenticator");
	}

	@GET
	@Path("version")
	@Produces(MediaType.APPLICATION_JSON)
	public String getVersion() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		JsonGenerator gen = Json.createGenerator(baos);
		gen.writeStartObject().write("version", Constants.API_VERSION).writeEnd();
		gen.close();
		return baos.toString();
	}

	@POST
	@Path("authenticate")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public String authenticate(@FormParam("json") String jsonString) throws AuthnException {

		ByteArrayInputStream s = new ByteArrayInputStream(jsonString.getBytes());

		String username = null;
		String password = null;
		String ip = null;
		try (JsonReader r = Json.createReader(s)) {
			JsonObject o = r.readObject();
			for (JsonValue c : o.getJsonArray("credentials")) {
				JsonObject credential = (JsonObject) c;
				if (credential.containsKey("username")) {
					username = credential.getString("username");
				} else if (credential.containsKey("password")) {
					password = credential.getString("password");
				}
			}
			if (o.containsKey("ip")) {
				ip = o.getString("ip");
			}

		}

		logger.debug("Login request by: " + username);

		if (username == null || username.isEmpty()) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "username cannot be null or empty.");
		}

		if (password == null || password.isEmpty()) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "password cannot be null or empty.");
		}

		if (addressChecker != null) {
			try {
				if (!addressChecker.check(ip)) {
					throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN,
							"authn_ldap does not allow log in from your IP address " + ip);
				}
			} catch (AddressCheckerException e) {
				throw new AuthnException(HttpURLConnection.HTTP_INTERNAL_ERROR, e.getClass() + " " + e.getMessage());
			}
		}

		logger.info("Checking username/password with ldap server");

		try {
			String bindPrincipal = username;
			Attribute mappedAttribute = null;
			Hashtable<Object, Object> bindEnv = new Hashtable<>(authEnv);
			if (presearchSecurityPrincipal != null) {
				Hashtable<Object, Object> searchEnv = new Hashtable<>(authEnv);
				searchEnv.put(Context.SECURITY_PRINCIPAL, presearchSecurityPrincipal);
				searchEnv.put(Context.SECURITY_CREDENTIALS, presearchSecurityCredentials);

				LdapContext searchCtx = new InitialLdapContext(searchEnv, null);
				try {
					SearchControls ctls = new SearchControls();
					ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
					ctls.setCountLimit(2);
					ctls.setTimeLimit(0);
					ctls.setReturningAttributes(new String[] { ldapAttribute });
					NamingEnumeration<SearchResult> results = searchCtx.search(ldapBase,
							ldapFilter.replace("%", "{0}"), new Object[] { username }, ctls);
					try {
						if (!results.hasMore()) {
							throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN,
									AUTHENTICATION_FAILED);
						}
						SearchResult sr = results.next();
						if (results.hasMore()) {
							throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN,
									AUTHENTICATION_FAILED);
						}
						bindPrincipal = sr.getNameInNamespace();
						mappedAttribute = sr.getAttributes().get(ldapAttribute);
					} finally {
						results.close();
					}
					logger.debug("security principal resolved to " + bindPrincipal + " via presearch");
				} finally {
					searchCtx.close();
				}
			}
			bindEnv.put(Context.SECURITY_PRINCIPAL, securityPrincipal.replace("%", bindPrincipal));
			bindEnv.put(Context.SECURITY_CREDENTIALS, password);

			LdapContext m_ctx = new InitialLdapContext(bindEnv, null);
			if (ldapBase != null && presearchSecurityPrincipal == null) {
				SearchControls ctls = new SearchControls();
				ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
				ctls.setCountLimit(0);
				ctls.setTimeLimit(0);
				NamingEnumeration<SearchResult> results = m_ctx.search(ldapBase, ldapFilter.replace("%", "{0}"),
						new Object[] { username }, ctls);
				if (!results.hasMoreElements()) {
					throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN,
							"Unable to locate user in LDAP directory.");
				}
				username = (String) results.nextElement().getAttributes().get(ldapAttribute).get();
				logger.debug("username changed to " + username + " from ldap search");
			}
			m_ctx.close();
			if (presearchSecurityPrincipal != null) {
				if (mappedAttribute == null || mappedAttribute.size() == 0) {
					throw new AuthnException(HttpURLConnection.HTTP_INTERNAL_ERROR,
							"LDAP attribute " + ldapAttribute + " must have at least one value.");
				}
				Object value = mappedAttribute.get();
				if (!(value instanceof String)) {
					throw new AuthnException(HttpURLConnection.HTTP_INTERNAL_ERROR,
							"LDAP attribute " + ldapAttribute + " must contain text values.");
				}
				username = (String) value;
			}
		} catch (AuthenticationException e) {
			throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, AUTHENTICATION_FAILED);
		} catch (NamingException e) {
			String msg = e.getClass() + ": " + e.getMessage();
			logger.error(msg);
			throw new AuthnException(HttpURLConnection.HTTP_INTERNAL_ERROR, "LDAP authentication service error.");
		}

		if (userNameCase == Case.UPPER) {
			username = username.toUpperCase();
			logger.debug("username changed to " + username + " from upper request");
		} else if (userNameCase == Case.LOWER) {
			username = username.toLowerCase();
			logger.debug("username changed to " + username + " from lower request");
		}

		logger.info(username + " logged in succesfully" + (mechanism != null ? " by " + mechanism : ""));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (JsonGenerator gen = Json.createGenerator(baos)) {
			gen.writeStartObject().write("username", username);
			if (mechanism != null) {
				gen.write("mechanism", mechanism);
			}
			gen.writeEnd();
		}
		return baos.toString();

	}

	@GET
	@Path("description")
	@Consumes(MediaType.APPLICATION_FORM_URLENCODED)
	@Produces(MediaType.APPLICATION_JSON)
	public String getDescription() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try (JsonGenerator gen = Json.createGenerator(baos)) {
			gen.writeStartObject().writeStartArray("keys");
			gen.writeStartObject().write("name", "username").writeEnd();
			gen.writeStartObject().write("name", "password").write("hide", true).writeEnd();
			gen.writeEnd().writeEnd();
		}
		return baos.toString();
	}

}
