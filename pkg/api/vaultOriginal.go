package api

import (
	"fmt"	
	"os"
	"io/ioutil"	
	"errors"
	"net/http"
	"encoding/json"		
	"github.com/tidwall/gjson"
	"github.com/sirupsen/logrus"
	
)


func Login(path string, role string, jwt string, vaultRootToken string) (*http.Response, error) {
	url := fmt.Sprintf("%s/v1/auth/%s/login", os.Getenv("VAULT_ADDR"), path)

	st := make(map[string]interface{})
	st["role"] = role
	st["jwt"] = jwt	
	body, _ := json.Marshal(st)

	return httpDo("POST", url, body, "X-Vault-Token", vaultRootToken)
	
}


func CreateRole(path string, name string, saName string, saNamespace string, 
	            policyName string, vaultRootToken string) (bool){
	url := fmt.Sprintf("%s/v1/auth/%s/role/%s", os.Getenv("VAULT_ADDR"), path, name)

	st := make(map[string]interface{})
	st["bound_service_account_names"] = saName
	st["bound_service_account_namespaces"] = saNamespace
	arr := []string{policyName}
	st["policies"] = arr
	
	body, _ := json.Marshal(st)
	resp, err := httpDo("POST", url, body, "X-Vault-Token", vaultRootToken)
	if err != nil {
		logrus.Error(url, err)
		return false
	}	
	bodyByte, err := ioutil.ReadAll(resp.Body)
	logrus.Info(string(bodyByte))	
	return true
	
}

func IsKubernetesPathExist(path string, vaultRootToken string) (bool, error) {
	url := os.Getenv("VAULT_ADDR") + "/v1/sys/auth"	

	resp, err := httpDo("GET", url, nil, "X-Vault-Token", vaultRootToken)
	if err != nil {
		logrus.Error(url, err)
		return false, err
	}	
	bodyByte, err := ioutil.ReadAll(resp.Body)	
	bodyJson := make(map[string]interface{})
	json.Unmarshal(bodyByte, &bodyJson)
	if (bodyJson["errors"] != nil){
		return false, errors.New("failed")
	} else {
		if (bodyJson[path+"/"] != nil){
			return true, nil
		} else {
			return false, nil
		}
	}
}

func EnableKubernetes(path string, vaultRootToken string) (bool){
	url := fmt.Sprintf("%s/v1/sys/auth/%s", os.Getenv("VAULT_ADDR"), path)

	st := make(map[string]interface{})
	st["type"] = "kubernetes"
	body, _ := json.Marshal(st)

	_, err := httpDo("POST", url, body, "X-Vault-Token", vaultRootToken)
	if (err != nil){
		logrus.Error(url, err)
		return false
	}
	return true
}

func ConfigKubernetes(path string, host string, ca string, vaultRootToken string) (bool){
	url := fmt.Sprintf("%s/v1/auth/%s/config", os.Getenv("VAULT_ADDR"), path)

	st := make(map[string]interface{})
	st["kubernetes_host"] = host
	st["kubernetes_ca_cert"] = ca
	
	body, _ := json.Marshal(st)
	_, err := httpDo("POST", url, body, "X-Vault-Token", vaultRootToken)
	if (err != nil){
		logrus.Error(url, err)
		return false
	}
	return true
}

func CreateVaultPath(path string, vaultRootToken string) (bool){
	url := fmt.Sprintf("%s/v1/secret/data/%s", os.Getenv("VAULT_ADDR"), path)

	st := make(map[string]interface{})
	st["data"] = nil	
	
	body, _ := json.Marshal(st)	
	resp, err := httpDo("POST", url, body, "X-Vault-Token", vaultRootToken)	

	if (err != nil || resp.StatusCode != 200) {	
		bodyByte, _ := ioutil.ReadAll(resp.Body)
		logrus.Error(url, err, string(bodyByte))				
		return false		
	} 
	
	return true
}

func AddPolicy(name string, path string, vaultRootToken string) (bool){
	url := fmt.Sprintf("%s/v1/sys/policies/acl/%s", os.Getenv("VAULT_ADDR"), name)

	st := make(map[string]interface{})
	policy := fmt.Sprintf("path \"secret/data/%s/*\" { \n capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]  \n}", path)
	st["policy"] = policy		
	body, _ := json.Marshal(st)
	
	resp, err := httpDo("PUT", url, body, "X-Vault-Token", vaultRootToken)	
	if (err != nil) {
		logrus.Error(url, err)
		return false
	}
	bodyByte, err := ioutil.ReadAll(resp.Body)
	logrus.Info(string(bodyByte))	
	return true
}

func WriteSecrets(path string, data []byte, token string) (*http.Response, error){

	url := fmt.Sprintf("%s/v1/secret/data/%s", os.Getenv("VAULT_ADDR"), path)		
	return httpDo("POST", url, data, "X-Vault-Token", token)	
	
}

func ReadSecretKeys(path string, token string) (*http.Response, error){

	url := fmt.Sprintf("%s/v1/secret/metadata/%s/?list=true", os.Getenv("VAULT_ADDR"), path)		
	return httpDo("GET", url, nil, "X-Vault-Token", token)	
	
}

func ReadSecrets(path string, token string) (*http.Response, error){

	url := fmt.Sprintf("%s/v1/secret/data/%s", os.Getenv("VAULT_ADDR"), path)		
	return httpDo("GET", url, nil, "X-Vault-Token", token)	
	
}

func LoginWithK8s(clusterName string, namespaceName string, jwtToken string, 
	              vaultRootToken string) string {
	roleName := fmt.Sprintf("clusterName_%s_namespaceName_%s", clusterName, namespaceName)
	kubernetesPath := "kubernetes-" + clusterName
	respLogin, err := Login(kubernetesPath, roleName, jwtToken, vaultRootToken)	
	if ( err != nil ){
		logrus.Error(err)		
		return ""
	}
	bodyByteLogin, err := ioutil.ReadAll(respLogin.Body)
	logrus.Info(string(bodyByteLogin))	
	token := gjson.GetBytes(bodyByteLogin, "auth.client_token").String()
	return token	
}