import java.sql.*;
import javax.servlet.http.*;

public class UserController extends HttpServlet {
    private Connection conn;

    private ResultSet findUser(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findUser(name);
    }
}
