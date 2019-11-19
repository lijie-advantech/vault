package api

import (
	"fmt"
	"os"
	"encoding/json"	
	"strings"
	"io/ioutil"		
	"github.com/tidwall/sjson"
	"github.com/tidwall/gjson"
	"github.com/vault/vault/pkg/public"
)


func CreateConfigmap(clusterName string, namespaceName string, deploymentName string, 
	kubernetesPath string, template string) (bool){
	
	configmapName := deploymentName + "-vault-configmap"
	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/local/namespace/%s/configmap/%s", 
	    public.MP_ADDR, namespaceName, configmapName)	
	mpToken := public.MP_TOKEN

        fmt.Printf("mpurl is %s, mp token is %s\r\n", mpUrl, mpToken)

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

	mpUrl = fmt.Sprintf("%s/v1/datacenter/cluster/local/namespace/%s/configmap", 
	    public.MP_ADDR, namespaceName)	
	
	_, err = httpDo("POST", mpUrl, body, "Authorization", mpToken)	
	if ( err != nil ) {
	    fmt.Printf("MP create configmap fail:%v", err)	    
	    return false
	}
	return true
	
}

func DeletePod(clusterName string, namespaceName string, podName string) (bool) {

	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/local/namespace/%s/pod/%s", 
	    public.MP_ADDR, namespaceName, podName)	
	mpToken := public.MP_TOKEN

	_, err := httpDo("DELETE", mpUrl, nil, "Authorization", mpToken)	
	if ( err != nil ) {
	    fmt.Printf("MP delete pod fail:%v", err)	    
	    return false
	}
	return true
}

func AddDeploymentLabel(clusterName string, namespaceName string, deploymentName string) (bool) {
	
	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/local/namespace/%s/deployment/%s", 
	    public.MP_ADDR, namespaceName, deploymentName)	
	mpToken := public.MP_TOKEN

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
	mpUrl = fmt.Sprintf("%s/v1/datacenter/cluster/local/namespace/%s/deploymentpods/%s", 
		public.MP_ADDR, namespaceName, deploymentName)	
	respPod, err := httpDo("GET", mpUrl, nil, "Authorization", mpToken)
	if ( err != nil ) {
		fmt.Printf("MP get deployment fail:%v", err)
		return false
	}	
	podByte, err := ioutil.ReadAll(respPod.Body)	
	result := gjson.GetBytes( podByte, "#.metadata.name" )	
	for _, name := range result.Array() {		
		fmt.Printf("pod name is %s", name.String())
		DeletePod(clusterName, namespaceName, name.String())
	}
		
	return true
}
