import java.sql.*;
import javax.servlet.http.*;

public class UserController extends HttpServlet {
    private Connection conn;

    private ResultSet findUser(String name) throws SQLException {
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        stmt.setString(1, name);
        return stmt.executeQuery();
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findUser(name);
    }
}
