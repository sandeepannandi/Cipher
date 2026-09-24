package main

import "github.com/gin-gonic/gin"

func handler(c *gin.Context) {
	name := c.Query("name")
	findUser(name)
}
