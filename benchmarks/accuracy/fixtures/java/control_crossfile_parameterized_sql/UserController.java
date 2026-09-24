package com.example.demo;

import java.sql.*;
import javax.servlet.http.*;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        UserService.findByName(name);
    }
}
