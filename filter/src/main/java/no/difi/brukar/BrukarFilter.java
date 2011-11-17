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
    
    public void init(FilterConfig filterConfig) throws ServletException {
        config = filterConfig;
    }
    
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            req = (HttpServletRequest) request;
            res = (HttpServletResponse) response;
            session = req.getSession(true);
            
            if (session.getAttribute("brukar") == null) {
                BrukarApi brukarApi = new BrukarApi(config.getInitParameter("host"));
                service = new ServiceBuilder().provider(brukarApi).apiKey(config.getInitParameter("token")).apiSecret(config.getInitParameter("secret")).callback(req.getRequestURL().toString()).build();
                
                if (req.getParameter("oauth_token") != null) {
                    loadUser();
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
    
    protected void loadUser() throws IOException {
        Token requestToken = (Token) session.getAttribute("token");
        if (requestToken != null) {
            session.removeAttribute("token");
            
            Token accessToken = service.getAccessToken(requestToken, new Verifier("dummy"));
            session.setAttribute("brukar", accessToken);
            
            String url = req.getRequestURI();
            res.sendRedirect(url);
        } else {
            res.getWriter().print("No access.");
        }
    }
    
    public void destroy() {
    }
}
