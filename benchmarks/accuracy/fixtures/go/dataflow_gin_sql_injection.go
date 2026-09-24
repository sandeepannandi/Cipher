package main

import (
	"database/sql"
	"fmt"

	"github.com/gin-gonic/gin"
)

var db *sql.DB

func handler(c *gin.Context) {
	name := c.Query("name")
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	rows, err := db.QueryContext(c, query)
	_ = rows
	_ = err
}
