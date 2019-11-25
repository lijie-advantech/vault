package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

func GetVaultRootToken() (string, error) {
	curDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	bytes, err := ioutil.ReadFile(curDir + "/secrets/vault-secrets.txt")
	logrus.Info("Read vault-secrets.txt content is ", string(bytes))
	if err != nil {
		logrus.Error(err)
		return "", err
	}
	token := gjson.GetBytes(bytes, "VAULT_TOKEN").String()	
	if (token == "") {
		return "", errors.New("Get vault root token is empty")
	}
	logrus.Info("Vault root token is ", token)
	return token, nil
}

func ListSecrets(c *gin.Context) {
	vaultRootToken, err := GetVaultRootToken()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	mpToken := c.Request.Header["Authorization"][0][7:]
	clusterName := c.Param("clusterName")
	namespaceName := c.Param("namespaceName")
	path := c.Param("path")

	jwtToken, err := GetDefaultSecretToken(clusterName, namespaceName, mpToken)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	token, err := LoginWithK8s(clusterName, namespaceName, jwtToken, vaultRootToken)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	secretPath := fmt.Sprintf("clusterName/%s/namespaceName/%s/%s", clusterName,
		namespaceName, path)
	resp, err := ReadSecrets(secretPath, token)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	bodyByte, err := ioutil.ReadAll(resp.Body)
	bodyJson := make(map[string]interface{})
	json.Unmarshal(bodyByte, &bodyJson)
	c.JSON(resp.StatusCode, bodyJson)

}

func ListSecretKeys(c *gin.Context) {
	vaultRootToken, err := GetVaultRootToken()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	clusterName := c.Param("clusterName")
	namespaceName := c.Param("namespaceName")

	secretPath := fmt.Sprintf("clusterName/%s/namespaceName/%s", clusterName, namespaceName)
	resp, err := ReadSecretKeys(secretPath, vaultRootToken)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	bodyByte, err := ioutil.ReadAll(resp.Body)
	if (err != nil) {
		c.JSON(500, gin.H{"error": err.Error()})
		return 
	}

	bodyJson := make(map[string]interface{})
	json.Unmarshal(bodyByte, &bodyJson)
	c.JSON(resp.StatusCode, bodyJson)

}

func EnableVault(c *gin.Context) {
	vaultRootToken, err := GetVaultRootToken()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	clusterName := c.Param("clusterName")
	namespaceName := c.Param("namespaceName")
	kubernetesPath := "kubernetes-" + clusterName
	policyName := fmt.Sprintf("clusterName_%s_namespaceName_%s", clusterName, namespaceName)
	dataPath := fmt.Sprintf("clusterName/%s/namespaceName/%s", clusterName, namespaceName)
	roleName := policyName
	saName := "default" //later modify as default
	saNamespace := namespaceName

	err = CreateVaultPath(dataPath+"/default", vaultRootToken)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	err = AddPolicy(policyName, dataPath, vaultRootToken)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	err = CreateRole(kubernetesPath, roleName, saName, saNamespace, policyName, vaultRootToken)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "success"})
}

func CreateSecrets(c *gin.Context) {
	vaultRootToken, err := GetVaultRootToken()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	
	mpToken := c.Request.Header["Authorization"][0][7:]
	clusterName := c.Param("clusterName")
	namespaceName := c.Param("namespaceName")
	path := c.Param("path")

	jwtToken, err := GetDefaultSecretToken(clusterName, namespaceName, mpToken)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	token, err := LoginWithK8s(clusterName, namespaceName, jwtToken, vaultRootToken)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	logrus.Info("Vault token is ", token)

	secretPath := fmt.Sprintf("clusterName/%s/namespaceName/%s/%s", clusterName,
		namespaceName, path)
	buf := make([]byte, 1024)
	n, _ := c.Request.Body.Read(buf)
	resp, err := WriteSecrets(secretPath, buf[0:n], token)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	bodyByte, err := ioutil.ReadAll(resp.Body)
	bodyJson := make(map[string]interface{})
	json.Unmarshal(bodyByte, &bodyJson)
	c.JSON(resp.StatusCode, bodyJson)

}

func InjectSidecar(c *gin.Context) {

	mpToken := c.Request.Header["Authorization"][0][7:]
	clusterName := c.Param("clusterName")
	namespaceName := c.Param("namespaceName")
	deploymentName := c.Param("deploymentName")
	body, _ := ioutil.ReadAll(c.Request.Body)
	path := gjson.GetBytes(body, "path")
	kubernetesPath := "kubernetes-" + clusterName
	var template string
	template = fmt.Sprintf("{{- with secret \"secret/data/clusterName/%s/namespaceName/%s/%s\" }}\r\n",
		clusterName, namespaceName, path)
	result := gjson.GetBytes(body, "keys")
	for _, name := range result.Array() {
		template += name.String() + ":" + "{{ .Data.data." + name.String() + " }}\r\n"
	}
	template += "{{ end }}"
	logrus.Info("Consul-template is ", template)

	err := CreateConfigmap(clusterName, namespaceName, deploymentName,
		kubernetesPath, template, mpToken)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	err = AddDeploymentLabel(clusterName, namespaceName, deploymentName, mpToken)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	err = DeleteDeploymentPod(clusterName, namespaceName, deploymentName, mpToken)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "success"})

}
