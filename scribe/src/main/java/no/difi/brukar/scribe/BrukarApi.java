package no.difi.brukar.scribe;

import org.scribe.builder.api.DefaultApi10a;
import org.scribe.model.Token;

public class BrukarApi extends DefaultApi10a {

	private String host;

	public BrukarApi(String host) {
		this.host = host;
	}
	
	@Override
	public String getAccessTokenEndpoint() {
		return host + "server/oauth/access_token";
	}

	@Override
	public String getAuthorizationUrl(Token token) {
		return host + String.format("server/oauth/authorize?oauth_token=%s", token.getToken());
	}

	@Override
	public String getRequestTokenEndpoint() {
		return host + "server/oauth/request_token";
	}
	
	public String getHost() {
		return host;
	}
}
