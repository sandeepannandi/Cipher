package com.example.demo;

import java.sql.*;

public class UserService {
    private static Connection conn;

    public static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = ?";
        PreparedStatement stmt = conn.prepareStatement(sql);
        stmt.setString(1, name);
        return stmt.executeQuery();
    }
}
