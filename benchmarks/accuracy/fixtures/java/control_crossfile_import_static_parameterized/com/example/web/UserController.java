package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import static com.example.service.UserService.findByName;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findByName(name);
    }
}
