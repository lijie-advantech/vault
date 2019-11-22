
package api

import (
	"fmt"	
    "os"
	"io/ioutil"	
	"encoding/json"	
	"github.com/gin-gonic/gin"	
	"github.com/tidwall/gjson"
	"github.com/sirupsen/logrus"	
)

func GetVaultRootToken() (string){
	curDir, _ := os.Getwd()	
	bytes, err := ioutil.ReadFile(curDir + "/secrets/vault-secrets.txt")
	logrus.Info("Read vault-secrets.txt content is ", string(bytes))		
	if err != nil {		
		logrus.Error(err)		
		return ""
	}	
	token := gjson.GetBytes(bytes, "VAULT_TOKEN").String()	
	logrus.Info("Vault root token is ", token)	
	return token
}

func ListSecrets(c *gin.Context) {
	vaultRootToken := GetVaultRootToken()
	if (vaultRootToken == "") {		
		c.JSON(500, gin.H{"error": "Get vault root token fail",})
		return
	}
    mpToken := c.Request.Header["Authorization"][0][7:]	
	clusterName := c.Param("clusterName")
	namespaceName := c.Param("namespaceName")	
	path := c.Param("path")
	
	jwtToken := GetDefaultSecretToken(clusterName, namespaceName, mpToken)
	if (jwtToken == "") {
		c.JSON(500, gin.H{"error": "Get jwt token fail",})
		return
	}
	
	token := LoginWithK8s(clusterName, namespaceName, jwtToken, vaultRootToken)
	if (token == "") {
		c.JSON(500, gin.H{"error": "Get vault token fail",})
		return
	}

	secretPath := fmt.Sprintf("clusterName/%s/namespaceName/%s/%s", clusterName, 
        namespaceName, path)	
	resp, err := ReadSecrets(secretPath, token)
	if ( err != nil ) {		
		c.JSON(500, gin.H{"error": "ReadSecrets fail",})
		return
	}
	bodyByte, err := ioutil.ReadAll(resp.Body)	
	bodyJson := make(map[string]interface{})
	json.Unmarshal(bodyByte, &bodyJson)
	c.JSON(resp.StatusCode, bodyJson)

}


func ListSecretKeys(c *gin.Context) {
	vaultRootToken := GetVaultRootToken()
	if (vaultRootToken == "") {		
		c.JSON(500, gin.H{"error": "Get vault root token fail",})
		return
	}
    mpToken := c.Request.Header["Authorization"][0][7:]	
	clusterName := c.Param("clusterName")
	namespaceName := c.Param("namespaceName")	
	
	jwtToken := GetDefaultSecretToken(clusterName, namespaceName, mpToken)
	if (jwtToken == "") {
		c.JSON(500, gin.H{"error": "Get jwt token fail",})
		return
	}
	
	token := LoginWithK8s(clusterName, namespaceName, jwtToken, vaultRootToken)
	if (token == "") {
		c.JSON(500, gin.H{"error": "Get vault token fail",})
		return
	}

	secretPath := fmt.Sprintf("clusterName/%s/namespaceName/%s", clusterName, 
        namespaceName)	
	resp, err := ReadSecretKeys(secretPath, token)
	if ( err != nil ) {		
		c.JSON(500, gin.H{"error": "ReadSecretKeys fail",})
		return
	}
	bodyByte, err := ioutil.ReadAll(resp.Body)	
	bodyJson := make(map[string]interface{})
	json.Unmarshal(bodyByte, &bodyJson)
	c.JSON(resp.StatusCode, bodyJson)



}

func EnableVault(c *gin.Context) {
	vaultRootToken := GetVaultRootToken()
	if (vaultRootToken == "") {		
		c.JSON(500, gin.H{"error": "Get vault root token fail",})
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

	if (!CreateVaultPath(dataPath + "/default", vaultRootToken)){		
		c.JSON(500, gin.H{"error": "CreateVaultPath fail",})
		return
	}

	/*
	kubernetesHost := "https://ensaas-190-aks-3e4c4b-dc10bcfc.hcp.southeastasia.azmk8s.io:443"
	kubernetesCaCert, err := ioutil.ReadFile("ca.txt")	
	pathExist, err := IsKubernetesPathExist(kubernetesPath)	
	if (err != nil) {
		fmt.Printf("IsKubernetesPathExist fail:%v\r\n", err)
		c.JSON(500, gin.H{"error": "IsKubernetesPathExist fail",})
	} else {
		if (!pathExist) {			
			if (!EnableKubernetes(kubernetesPath)) {
				fmt.Println("EnableKubernetes fail")
				c.JSON(500, gin.H{"error": "EnableKubernetes fail",})
			}		
						
			if (!ConfigKubernetes(kubernetesPath, kubernetesHost, 
				string(kubernetesCaCert))) {				
				fmt.Println("ConfigKubernetes fail")
				c.JSON(500, gin.H{"error": "ConfigKubernetes fail",})
			}			
		}
	}*/
	
	if (!AddPolicy(policyName, dataPath, vaultRootToken)) {		
		c.JSON(500, gin.H{"error": "AddPolicy fail",})
		return
	}
	if (!CreateRole(kubernetesPath, roleName, saName, saNamespace, policyName, vaultRootToken)){		
		c.JSON(500, gin.H{"error": "CreateRole fail",})
		return
	}
	c.JSON(200, gin.H{"message": "success",})
}



func CreateSecrets(c *gin.Context) {
    vaultRootToken := GetVaultRootToken()
	if (vaultRootToken == "") {		
		c.JSON(500, gin.H{"error": "Get vault root token fail",})
		return
	}

	mpToken := c.Request.Header["Authorization"][0][7:]	
	clusterName := c.Param("clusterName")
	namespaceName := c.Param("namespaceName")
	path := c.Param("path")
		
	jwtToken := GetDefaultSecretToken(clusterName, namespaceName, mpToken)
	if (jwtToken == "") {
		c.JSON(500, gin.H{"error": "Get jwt token fail",})
		return
	}
	
	token := LoginWithK8s(clusterName, namespaceName, jwtToken, vaultRootToken)
	if (token == "") {
		c.JSON(500, gin.H{"error": "Get vault token fail",})
		return
	}
	logrus.Info("Vault token is ", token)

	secretPath := fmt.Sprintf("clusterName/%s/namespaceName/%s/%s", clusterName, 
        namespaceName, path)		
	buf := make([]byte, 1024)
	n, _ := c.Request.Body.Read(buf)		
	resp, err := WriteSecrets(secretPath, buf[0:n], token)
	if ( err != nil ) {		
		c.JSON(500, gin.H{"error": "WriteSecrets fail",})
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
	body,_ := ioutil.ReadAll(c.Request.Body)
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

	if (!CreateConfigmap(clusterName, namespaceName, deploymentName, 
		    kubernetesPath, template, mpToken)) {		
		c.JSON(500, gin.H{"error": "CreateConfigmap fail",})
		return
	}
	if (!AddDeploymentLabel(clusterName, namespaceName, deploymentName, mpToken)) {
		c.JSON(500, gin.H{"error": "AddDeploymentLabel fail",})
		return
	}
	if (!DeleteDeploymentPod(clusterName, namespaceName, deploymentName, mpToken)) {
		c.JSON(500, gin.H{"error": "DeleteDeploymentPod fail",})
		return
	}
	c.JSON(200, gin.H{"message": "success",})

}
