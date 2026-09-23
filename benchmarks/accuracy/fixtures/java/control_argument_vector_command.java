import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class PingHandler {
    public Process ping(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        return new ProcessBuilder("ping", "-c", "1", host).start();
    }
}
