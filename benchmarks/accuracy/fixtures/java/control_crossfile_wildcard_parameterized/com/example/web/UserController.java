package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import com.example.service.*;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        UserService.findByName(name);
    }
}
