import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class PingHandler {
    public Process ping(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        String cmd = "ping -c 1 " + host;
        return new ProcessBuilder("sh", "-c", cmd).start();
    }
}
