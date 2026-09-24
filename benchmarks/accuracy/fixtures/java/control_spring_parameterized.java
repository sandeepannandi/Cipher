import java.sql.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    private Connection conn;

    @GetMapping("/user")
    public String getUser(@RequestParam String name) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        ResultSet rs = ps.executeQuery();
        return "ok";
    }
}
