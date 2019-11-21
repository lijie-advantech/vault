package api

import (
	"fmt"
	"os"
	"encoding/json"	
	"strings"
	"encoding/base64"
	"io/ioutil"		
	"github.com/tidwall/sjson"
	"github.com/tidwall/gjson"
	
)
func GetDefaultSecretToken(clusterName string, namespaceName string, mpToken string) string{
	//get secret token	
	var jwtToken string
	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/secrets", 
	    os.Getenv("MP_ADDR"), clusterName, namespaceName)	
	respSec, err := httpDo("GET", mpUrl, nil, "Authorization", mpToken)	
	if ( err != nil ) {
		fmt.Printf("MP get secrets fail:%v", err)		
		return ""
	}	
	respBodySec, err := ioutil.ReadAll(respSec.Body)
	fmt.Println(string(respBodySec))	
	if (respSec.StatusCode != 200) {
		fmt.Println(string(respBodySec))		
		return ""
	}	
	if ( err != nil ) {
		fmt.Printf("MP get secret body fail:%v", err)		
		return ""
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
	return jwtToken
}

func CreateConfigmap(clusterName string, namespaceName string, deploymentName string, 
	kubernetesPath string, template string, mpToken string) (bool){
	
	configmapName := deploymentName + "-vault-configmap"
	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/configmap/%s", 
	    os.Getenv("MP_ADDR"), clusterName, namespaceName, configmapName)		
    resp, err := httpDo("DELETE", mpUrl, nil, "Authorization", mpToken)	
	bodyByte, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(bodyByte))
	if ( err != nil ) {
	    fmt.Printf("MP delete configmap fail:%v", err)	    
	    return false
	}

	roleName := fmt.Sprintf("clusterName_%s_namespaceName_%s", clusterName, namespaceName)
	curDir, _ := os.Getwd()
	vacofByte, err := ioutil.ReadFile(curDir + "/vault-agent-config.hcl")
	if err != nil {
	    fmt.Printf("Read vault-agent-config fail: %s", err)	    
	    return false
	}
	vaconfStr := strings.Replace(string(vacofByte), "VAULT_ROLE", roleName, -1)
	vaconfStr = strings.Replace(vaconfStr, "KUBERNETES_PATH", kubernetesPath, -1)

	ctconfByte, err := ioutil.ReadFile(curDir + "/consul-template-config.hcl")
	if err != nil {
	    fmt.Printf("Read consul-template-config fail: %s", err)	    
	    return false
	}
	ctconfStr := strings.Replace(string(ctconfByte), "CONSUL_TEMPLATE", template, -1)

	st := make(map[string]interface{})	

	metaObj := make(map[string]string)
	metaObj["name"] = configmapName

	dataObj := make(map[string]string)
	dataObj["vault-agent-config.hcl"] = vaconfStr
	dataObj["consul-template-config.hcl"] = ctconfStr

	st["metadata"] = metaObj
	st["data"] = dataObj

	body, _ := json.Marshal(st)

	mpUrl = fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/configmap", 
	    os.Getenv("MP_ADDR"), clusterName, namespaceName)	
	
	_, err = httpDo("POST", mpUrl, body, "Authorization", mpToken)	
	if ( err != nil ) {
	    fmt.Printf("MP create configmap fail:%v", err)	    
	    return false
	}
	return true
	
}

func DeletePod(clusterName string, namespaceName string, podName string, mpToken string) (bool) {

	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/pod/%s", 
	    os.Getenv("MP_ADDR"), clusterName, namespaceName, podName)	
	
	resp, err := httpDo("DELETE", mpUrl, nil, "Authorization", mpToken)	
	if ( err != nil || resp.StatusCode != 200 ) {
	    fmt.Printf("MP delete pod fail:%v", err)	    
	    return false
	}
	return true
}

func AddDeploymentLabel(clusterName string, namespaceName string, deploymentName string,
	                    mpToken string) (bool) {
	
	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/deployment/%s", 
	    os.Getenv("MP_ADDR"), clusterName, namespaceName, deploymentName)		
	//get deployment
	respDeploy, err := httpDo("GET", mpUrl, nil, "Authorization", mpToken)	
	if ( err != nil ) {
	    fmt.Printf("MP get pod fail:%v", err)	    
	    return false
	}
	deployByte, err := ioutil.ReadAll(respDeploy.Body)	
	//set label in deployment
	outDeployByte, _ := sjson.SetBytes(deployByte, "spec.template.metadata.labels.vault-inject", "true")

	//add label in deployment
	_, err = httpDo("PUT", mpUrl, outDeployByte, "Authorization", mpToken)	
	if ( err != nil ) {
	    fmt.Printf("MP add label fail:%v", err)	    
	    return false
	}

	//get pods from deployment
	mpUrl = fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/deploymentpods/%s", 
		os.Getenv("MP_ADDR"), clusterName, namespaceName, deploymentName)	
	respPod, err := httpDo("GET", mpUrl, nil, "Authorization", mpToken)
	if ( err != nil ) {
		fmt.Printf("MP get deployment fail:%v", err)
		return false
	}	
	podByte, err := ioutil.ReadAll(respPod.Body)	
	result := gjson.GetBytes( podByte, "#.metadata.name" )	
	for _, name := range result.Array() {		
		fmt.Printf("pod name is %s", name.String())
		if ( !DeletePod(clusterName, namespaceName, name.String(), mpToken) ) {			
			return false
		}
	}
		
	return true
}
