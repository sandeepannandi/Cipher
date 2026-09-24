import java.sql.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    private Connection conn;

    @GetMapping("/user")
    public String getUser(
            @RequestParam String name,
            @RequestParam String city) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE city = ?");
        ps.setString(1, city);
        ResultSet rs = ps.executeQuery();
        return "ok";
    }
}
