package lol.maki.dev.account;

import lol.maki.dev.Tools.Tools;
import lol.maki.dev.config.JwtFilter;
import lol.maki.dev.config.OauthProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
public class AccountController {
    private final List<ClientDetails> clientDetails;
    private JwtFilter jwtFilter;
    @Value("${oauth.clients[0].additional-information.url}")
    private String oauthClientUrl;

    public AccountController(OauthProperties oauthProperties) {
        this.clientDetails = oauthProperties.getClients().values()
                .stream()
                .filter(c -> c.getAdditionalInformation().containsKey("name"))
                .collect(Collectors.toList());
    }
    //    @GetMapping(path = "/")
//    public String index(Model model, @AuthenticationPrincipal AccountUserDetails userDetails) {
//        model.addAttribute("account", userDetails.getAccount());
//        model.addAttribute("clientDetails", clientDetails);
//        return "index";
//    }
    @GetMapping(path = "/")
    public void index(HttpServletRequest request, HttpServletResponse response, @AuthenticationPrincipal AccountUserDetails userDetails) throws IOException {
        List<String> authServiceUrls = getAuthServiceUrls(clientDetails);
        for (String url : authServiceUrls) {
            if (Tools.compareValue(oauthClientUrl, url)) {
                String redirectUrl = "http://localhost:9999" + "?redirect=" + url;
                response.sendRedirect(redirectUrl);
            }
        }
    }

    // Utility method to get the auth service URLs
    private List<String> getAuthServiceUrls(List<ClientDetails> clientDetails) {
        List<String> authServiceUrls = new ArrayList<>();
        for (ClientDetails clientDetail : clientDetails) {
            Map<String, Object> additionalInfo = clientDetail.getAdditionalInformation();
            // Assuming 'url' key in additional information holds the URLs
            if (additionalInfo.containsKey("url")) {
                Object urlInfo = additionalInfo.get("url");
                if (urlInfo instanceof String) {
                    authServiceUrls.add((String) urlInfo);
                } else if (urlInfo instanceof Collection) {
                    for (Object url : (Collection<?>) urlInfo) {
                        if (url instanceof String) {
                            authServiceUrls.add((String) url);
                        }
                    }
                }
            }
        }
        return authServiceUrls;
    }

//    @GetMapping(path = "/")
//    public AccountUserDetails getToken(@AuthenticationPrincipal AccountUserDetails userDetails) {
//        return userDetails;
//    }

    @GetMapping(path = "login")
    public String login() {
        return "login";
    }
}
