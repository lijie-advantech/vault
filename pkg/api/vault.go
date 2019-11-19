
package api

import (
	"fmt"	
        "os"
	"io/ioutil"	
	"strings"
	"encoding/base64"
	"encoding/json"	
	"github.com/gin-gonic/gin"	
	"github.com/tidwall/gjson"
	"github.com/vault/vault/pkg/public"
)

func GetSecret() {
	curDir, _ := os.Getwd()
	bytes, err := ioutil.ReadFile(curDir + "/secrets/vault-secrets.txt")
	fmt.Printf("Read content is %s\r\n", string(bytes))
	if err != nil {
		fmt.Printf("Read vault-secrets.txt fail %v", err)
		return

	}

	public.VAULT_ADDR = gjson.GetBytes(bytes, "VAULT_ADDR").String()
	public.VAULT_TOKEN = gjson.GetBytes(bytes, "VAULT_TOKEN").String()
	public.MP_ADDR = gjson.GetBytes(bytes, "MP_ADDR").String()
	public.MP_TOKEN = gjson.GetBytes(bytes, "MP_TOKEN").String()
	fmt.Printf("vault_addr is %s, vault_token is %s, mp_addr is %s, mp_token is %s ",
		public.VAULT_ADDR, public.VAULT_TOKEN, public.MP_ADDR, public.MP_TOKEN)

}

func EnableVault(c *gin.Context) {
        GetSecret()
	
	clusterName := c.Param("clusterName")
	namespaceName := c.Param("namespaceName")

	kubernetesPath := "kubernetes-" + clusterName
	policyName := fmt.Sprintf("clusterName_%s_namespaceName_%s", clusterName, namespaceName)
	dataPath := fmt.Sprintf("clusterName/%s/namespaceName/%s", clusterName, namespaceName)
	roleName := policyName
	saName := "default" //later modify as default
	saNamespace := namespaceName
	

	if (!CreateVaultPath(dataPath + "/default")){
		fmt.Println("CreateVaultPath fail")
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
	
	if (!AddPolicy(policyName, dataPath)) {		
		c.JSON(500, gin.H{"error": "AddPolicy fail",})
		return
	}
	if (!CreateRole(kubernetesPath, roleName, saName, saNamespace, policyName)){		
		c.JSON(500, gin.H{"error": "CreateRole fail",})
		return
	}
	c.JSON(200, gin.H{"message": "success",})
}



func CreateSecrets(c *gin.Context) {
        GetSecret()

	clusterName := c.Param("clusterName")
	namespaceName := c.Param("namespaceName")
	path := c.Param("path")
	kubernetesPath := "kubernetes-" + clusterName
	
	//get secret token	
	var jwtToken string
	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/local/namespace/%s/secrets", 
	    public.MP_ADDR, namespaceName)	
	mpToken := public.MP_TOKEN
	respSec, err := httpDo("GET", mpUrl, nil, "Authorization", mpToken)	
	if ( err != nil ) {
		fmt.Printf("MP get secrets fail:%v", err)
		c.JSON(500, gin.H{"error": "MP get secret fail",})
		return
	}	
	respBodySec, err := ioutil.ReadAll(respSec.Body)
	fmt.Println(string(respBodySec))	
	if (respSec.StatusCode != 200) {
		fmt.Println(string(respBodySec))
		c.JSON(500, gin.H{"error": "MP get secret fail",})
		return
	}	
	if ( err != nil ) {
		fmt.Printf("MP get secret body fail:%v", err)
		c.JSON(500, gin.H{"error": "MP get secret body fail",})
		return
	}		
	result := gjson.GetBytes(respBodySec, `items`)	
	for _, name := range result.Array() {
		secretName := gjson.Get(name.String(), `metadata.name`)
		fmt.Printf("secret name is: %s\r\n", secretName)
		if (strings.Contains(secretName.String(), "default-token")) {
			jwtStr := gjson.Get(name.String(), `data.token`)			
			jwtBase64, _ := base64.StdEncoding.DecodeString(jwtStr.String())
			jwtToken = string(jwtBase64)				
		}
	}
	fmt.Printf("jwt token is:%s\r\n", jwtToken)	
	
	roleName := fmt.Sprintf("clusterName_%s_namespaceName_%s", clusterName, namespaceName)
	respLogin, err := Login(kubernetesPath, roleName, jwtToken)	
	if ( err != nil ){
		fmt.Printf("Login fail:%v\r\n", err)
		c.JSON(500, gin.H{"error": "Login fail",})
		return
	}
	bodyByteLogin, err := ioutil.ReadAll(respLogin.Body)
	fmt.Println(string(bodyByteLogin))	
	token := gjson.GetBytes(bodyByteLogin, "auth.client_token").String()	

	secretPath := fmt.Sprintf("clusterName/%s/namespaceName/%s/%s", clusterName, 
        namespaceName, path)		
	buf := make([]byte, 1024)
	n, _ := c.Request.Body.Read(buf)	
	fmt.Printf("token is %s\r\n", token)
	resp, err := WriteSecrets(secretPath, buf[0:n], token)
	if ( err != nil ) {
		fmt.Printf("WriteSecrets fail:%v\r\n", err)
		c.JSON(500, gin.H{"error": "WriteSecrets fail",})
		return
	}
	bodyByte, err := ioutil.ReadAll(resp.Body)	
	bodyJson := make(map[string]interface{})
	json.Unmarshal(bodyByte, &bodyJson)
	c.JSON(resp.StatusCode, bodyJson)

}


func InjectSidecar(c *gin.Context) {
        GetSecret()

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
	fmt.Printf("template is %s", template)	                    

	if (!CreateConfigmap(clusterName, namespaceName, deploymentName, 
		    kubernetesPath, template)) {		
		c.JSON(500, gin.H{"error": "Create configmap fail",})
		return
	}
	if (!AddDeploymentLabel(clusterName, namespaceName, deploymentName)) {
		c.JSON(500, gin.H{"error": "Add label fail",})
		return
	}
	c.JSON(200, gin.H{"message": "success",})

}
