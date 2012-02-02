package no.difi.brukar;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import no.difi.brukar.scribe.BrukarApi;
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.Token;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;

public class BrukarFilter implements Filter {
    
    private FilterConfig config;
    private OAuthService service;
    private HttpServletRequest req;
    private HttpServletResponse res;
    private HttpSession session;
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        config = filterConfig;
    }
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            req = (HttpServletRequest) request;
            res = (HttpServletResponse) response;
            session = req.getSession(true);
            
            if (session.getAttribute("brukar") == null) {
                BrukarApi brukarApi = new BrukarApi(config.getInitParameter("host"));
                
                String _url = ((HttpServletRequest) request).getRequestURL().toString();
                String _query = ((HttpServletRequest) request).getQueryString();
            
                String url = _url + (_query == null ? "" : "?" + _query);
                
                service = new ServiceBuilder().provider(brukarApi).apiKey(config.getInitParameter("token")).apiSecret(config.getInitParameter("secret")).callback(url).build();
                
                if (req.getParameter("oauth_token") != null) {
                    loadUser(url);
                } else {
                    requestLogin();
                }
            } else {
                chain.doFilter(request, response);
            }
        }
    }
    
    protected void requestLogin() throws IOException {
        Token requestToken = service.getRequestToken();
        session.setAttribute("token", requestToken);
        
        res.sendRedirect(service.getAuthorizationUrl(requestToken));
    }
    
    protected void loadUser(String url) throws IOException {
        Token requestToken = (Token) session.getAttribute("token");
        if (requestToken != null) {
            session.removeAttribute("token");
            
            Token accessToken = service.getAccessToken(requestToken, new Verifier("dummy"));
            session.setAttribute("brukar", accessToken);

            res.sendRedirect(url.substring(0, url.indexOf("oauth_token=") - 1));
        } else {
            res.getWriter().print("No access.");
        }
    }
    
    @Override
    public void destroy() {

    }
}
