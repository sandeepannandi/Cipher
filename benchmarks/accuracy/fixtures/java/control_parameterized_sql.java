import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.servlet.http.HttpServletRequest;

public class UserLookup {
    public ResultSet find(HttpServletRequest request, Connection conn) throws SQLException {
        String name = request.getParameter("name");
        PreparedStatement ps = conn.prepareStatement("SELECT id, email FROM users WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery();
    }
}
