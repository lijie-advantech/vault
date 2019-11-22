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
	"github.com/sirupsen/logrus"	
)
func GetDefaultSecretToken(clusterName string, namespaceName string, mpToken string) string{
	//get secret token	
	var jwtToken string
	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/secrets", 
	    os.Getenv("MP_ADDR"), clusterName, namespaceName)	
	respSec, err := httpDo("GET", mpUrl, nil, "Authorization", mpToken)	
	respBodySec, errRead := ioutil.ReadAll(respSec.Body)	
	if ( err != nil || respSec.StatusCode != 200 ) {		
		logrus.Error(mpUrl, err, string(respBodySec))		
		return ""
	} 		
	if ( errRead != nil ) {
		logrus.Error(errRead)		
		return ""
	}		
	result := gjson.GetBytes(respBodySec, `items`)	
	for _, name := range result.Array() {
		secretName := gjson.Get(name.String(), `metadata.name`)
		logrus.Info("secret name is ", secretName)
		if (strings.Contains(secretName.String(), "default-token")) {
			jwtStr := gjson.Get(name.String(), `data.token`)			
			jwtBase64, _ := base64.StdEncoding.DecodeString(jwtStr.String())
			jwtToken = string(jwtBase64)				
		}
	}
	logrus.Info("Jwt token is ", jwtToken)	
	return jwtToken
}

func CreateConfigmap(clusterName string, namespaceName string, deploymentName string, 
	kubernetesPath string, template string, mpToken string) (bool){
	
	configmapName := deploymentName + "-vault-configmap"
	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/configmap/%s", 
	    os.Getenv("MP_ADDR"), clusterName, namespaceName, configmapName)		
    resp, err := httpDo("DELETE", mpUrl, nil, "Authorization", mpToken)		
	if ( err != nil || resp.StatusCode != 200 ) {
		respByte, _ := ioutil.ReadAll(resp.Body)
	    logrus.Error(mpUrl, err, string(respByte))	    
	    return false
	}

	roleName := fmt.Sprintf("clusterName_%s_namespaceName_%s", clusterName, namespaceName)
	curDir, _ := os.Getwd()
	vacofByte, err := ioutil.ReadFile(curDir + "/vault-agent-config.hcl")
	if err != nil {
	    logrus.Error(err)	    
	    return false
	}
	vaconfStr := strings.Replace(string(vacofByte), "VAULT_ROLE", roleName, -1)
	vaconfStr = strings.Replace(vaconfStr, "KUBERNETES_PATH", kubernetesPath, -1)

	ctconfByte, err := ioutil.ReadFile(curDir + "/consul-template-config.hcl")
	if err != nil {
	    logrus.Error(err)	    
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
	
	resp, err = httpDo("POST", mpUrl, body, "Authorization", mpToken)	
	if ( err != nil || resp.StatusCode != 200 ) {
		respByte, _ := ioutil.ReadAll(resp.Body)
	    logrus.Error(mpUrl, err, string(respByte))	    
	    return false
	}
	return true
	
}

func DeletePod(clusterName string, namespaceName string, podName string, mpToken string) (bool) {

	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/pod/%s", 
	    os.Getenv("MP_ADDR"), clusterName, namespaceName, podName)	
	
	resp, err := httpDo("DELETE", mpUrl, nil, "Authorization", mpToken)	
	if ( err != nil || resp.StatusCode != 200 ) {
		respByte, _ := ioutil.ReadAll(resp.Body)
	    logrus.Error(mpUrl, err, string(respByte))	    
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
	deployByte, _ := ioutil.ReadAll(respDeploy.Body)	
	if ( err != nil || respDeploy.StatusCode != 200 ) {
	    logrus.Error(mpUrl, err, string(deployByte))	    
	    return false
	}
	
	//set label in deployment
	outDeployByte, _ := sjson.SetBytes(deployByte, "spec.template.metadata.labels.vault-inject", "true")

	//add label in deployment
	resp, err := httpDo("PUT", mpUrl, outDeployByte, "Authorization", mpToken)	
	if ( err != nil || resp.StatusCode != 200 ) {
		respByte, _ := ioutil.ReadAll(resp.Body)
	    logrus.Error(mpUrl, err, string(respByte))	    
	    return false
	}
	return true
}

func DeleteDeploymentPod(clusterName string, namespaceName string, deploymentName string,
	                  mpToken string) (bool) {
	//get pods from deployment
	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/deploymentpods/%s", 
		os.Getenv("MP_ADDR"), clusterName, namespaceName, deploymentName)	
	respPod, err := httpDo("GET", mpUrl, nil, "Authorization", mpToken)
	podByte, _ := ioutil.ReadAll(respPod.Body)	
	if ( err != nil || respPod.StatusCode != 200 ) {
		logrus.Error(mpUrl, err, string(podByte))
		return false
	}	
	
	result := gjson.GetBytes( podByte, "#.metadata.name" )	
	for _, name := range result.Array() {		
		logrus.Info("pod name is ", name.String())
		if ( !DeletePod(clusterName, namespaceName, name.String(), mpToken) ) {			
			return false
		}
	}		
	return true
}


	

