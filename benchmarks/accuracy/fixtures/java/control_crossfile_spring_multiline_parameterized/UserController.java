package com.example.demo;

import java.sql.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    @GetMapping("/user/{name}")
    public ResultSet getUser(
            @PathVariable String name) throws SQLException {
        return UserService.findByName(name);
    }
}
