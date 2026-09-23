import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class UserLookup {
    public ResultSet find(HttpServletRequest request, Connection conn) throws SQLException {
        String name = request.getParameter("name");
        String sql = "SELECT id, email FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
