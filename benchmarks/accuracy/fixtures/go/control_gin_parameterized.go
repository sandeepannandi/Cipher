package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"
)

var db *sql.DB

func handler(c *gin.Context) {
	name := c.Query("name")
	rows, err := db.QueryContext(c, "SELECT * FROM users WHERE name = $1", name)
	_ = rows
	_ = err
}
