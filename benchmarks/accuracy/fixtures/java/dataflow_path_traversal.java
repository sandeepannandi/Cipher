import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class DownloadHandler {
    public byte[] download(HttpServletRequest request) throws IOException {
        String requested = request.getParameter("file");
        File target = new File("uploads", requested);
        try (FileInputStream in = new FileInputStream(target)) {
            return in.readAllBytes();
        }
    }
}
