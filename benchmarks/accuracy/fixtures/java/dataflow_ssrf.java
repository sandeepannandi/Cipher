import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;

public class PreviewHandler {
    public InputStream preview(HttpServletRequest request) throws IOException {
        String target = request.getParameter("url");
        URL endpoint = new URL(target);
        HttpURLConnection conn = (HttpURLConnection) endpoint.openConnection();
        return conn.getInputStream();
    }
}
