import java.sql.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    private Connection conn;

    @GetMapping("/user")
    public String getUser(
            @RequestParam String name,
            @RequestParam String city) throws SQLException {
        String sql = "SELECT * FROM users WHERE city = '" + city + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        return "ok";
    }
}
