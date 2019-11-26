package main

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/vault/vault/pkg/api"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	_ "github.com/vault/vault/docs"
)

// @title Swagger Vault API
// @version 1.0
// @description This is vault api doc.

// @host 127.0.0.1:3001
// @BasePath /secret

// @securityDefinitions.basic BasicAuth

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization

func main() {
	router := gin.New()

	//router.Use(AuthMiddleWare())

	path := "secret/clusterName/:clusterName/namespaceName/:namespaceName"

	router.POST(path, api.EnableVault)
	router.GET(path, api.ListSecretKeys)
	router.GET(path+"/:path", api.ListSecrets)
	router.POST(path+"/:path", api.CreateSecrets)
	router.PUT(path+"/deploymentName/:deploymentName", api.InjectSidecar)

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	router.Run(":3001") // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}

func AuthMiddleWare() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenArr := ctx.Request.Header["Authorization"]
		if len(tokenArr) == 0 {
			ctx.JSON(500, gin.H{"error": "Token format error"})
			ctx.Abort()
		}
		tokenString := tokenArr[0]
		if strings.Index(tokenString, "Bearer ") == -1 {
			ctx.JSON(500, gin.H{"error": "Token format error"})
			ctx.Abort()
		}
		tokenString = tokenString[7:]
		fmt.Println(tokenString)
		ctx.Next()
	}
}
