package main

import (
	
	"github.com/gin-gonic/gin"	
	"github.com/vault/vault/pkg/api"		
)

func main() {	

	r := gin.Default()
	r.GET("/ping", getPing)

	r.POST("secret/clusterName/:clusterName/namespaceName/:namespaceName", api.EnableVault)
	r.POST("secret/clusterName/:clusterName/namespaceName/:namespaceName/:path", api.CreateSecrets)
	r.PUT("secret/clusterName/:clusterName/namespaceName/:namespaceName/deploymentName/:deploymentName", api.InjectSidecar)

       
	r.Run(":3001") // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")        
}

func getPing(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "pong",
	})
}
