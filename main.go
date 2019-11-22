package main

import (
	"fmt"
	"strings"
	"github.com/gin-gonic/gin"	
	"github.com/vault/vault/pkg/api"		
)



func main() {

	r := gin.Default()
	r.Use(AuthMiddleWare())
	r.GET("/ping", getPing)

	r.POST("secret/clusterName/:clusterName/namespaceName/:namespaceName", api.EnableVault)
	r.GET("secret/clusterName/:clusterName/namespaceName/:namespaceName", api.ListSecretKeys)
	r.GET("secret/clusterName/:clusterName/namespaceName/:namespaceName/:path", api.ListSecrets)	
	r.POST("secret/clusterName/:clusterName/namespaceName/:namespaceName/:path", api.CreateSecrets)
	r.PUT("secret/clusterName/:clusterName/namespaceName/:namespaceName/deploymentName/:deploymentName", api.InjectSidecar)
       
	r.Run(":3001") // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")        
}


func AuthMiddleWare() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenArr := ctx.Request.Header["Authorization"]
		if len(tokenArr) == 0 {			
            ctx.JSON(500, gin.H{"error": "Token format error",})	
			ctx.Abort()
		}
		tokenString := tokenArr[0]
		if strings.Index(tokenString, "Bearer ") == -1 {			
            ctx.JSON(500, gin.H{"error": "Token format error",})
			ctx.Abort()
		}
		tokenString = tokenString[7:]
		fmt.Println(tokenString)
		ctx.Next()
	}
}



func getPing(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "pong",
	})
}
