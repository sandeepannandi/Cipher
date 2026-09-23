import javax.servlet.http.HttpServletRequest;
import org.springframework.web.client.RestTemplate;

public class SearchHandler {
    private final RestTemplate restTemplate = new RestTemplate();

    public String search(HttpServletRequest request) {
        String term = request.getParameter("q");
        return restTemplate.postForObject("https://api.example.com/search", term, String.class);
    }
}
