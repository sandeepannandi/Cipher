import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;

public class DownloadHandler {
    public byte[] download(HttpServletRequest request) throws IOException {
        String requested = Paths.get(request.getParameter("file")).getFileName().toString();
        File target = new File("uploads", requested);
        try (FileInputStream in = new FileInputStream(target)) {
            return in.readAllBytes();
        }
    }
}
