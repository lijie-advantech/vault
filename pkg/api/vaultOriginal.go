package api

import (
	"fmt"	
	"io/ioutil"	
	"errors"
	"net/http"
	"encoding/json"		
	"github.com/vault/vault/pkg/public"
)


func Login(path string, role string, jwt string) (*http.Response, error) {
	url := fmt.Sprintf("%s/v1/auth/%s/login", public.VAULT_ADDR, path)

	st := make(map[string]interface{})
	st["role"] = role
	st["jwt"] = jwt	
	body, _ := json.Marshal(st)

	return httpDo("POST", url, body, "X-Vault-Token", public.VAULT_TOKEN)
	
}


func CreateRole(path string, name string, saName string, saNamespace string, policyName string) (bool){
	url := fmt.Sprintf("%s/v1/auth/%s/role/%s", public.VAULT_ADDR, path, name)

	st := make(map[string]interface{})
	st["bound_service_account_names"] = saName
	st["bound_service_account_namespaces"] = saNamespace
	arr := []string{policyName}
	st["policies"] = arr
	
	body, _ := json.Marshal(st)
	resp, err := httpDo("POST", url, body, "X-Vault-Token", public.VAULT_TOKEN)
	if err != nil {
		fmt.Printf("vault api v1/auth/kubernetes/role/:name fail:%v\r\n", err)
		return false
	}	
	bodyByte, err := ioutil.ReadAll(resp.Body)
	fmt.Println(string(bodyByte))	
	return true
	
}

func IsKubernetesPathExist(path string) (bool, error) {
	url := public.VAULT_ADDR + "/v1/sys/auth"	

	resp, err := httpDo("GET", url, nil, "X-Vault-Token", public.VAULT_TOKEN)
	if err != nil {
		fmt.Printf("vault api /v1/sys/auth fail:%v\r\n", err)
		return false, err
	}	
	bodyByte, err := ioutil.ReadAll(resp.Body)	
	fmt.Println(string(bodyByte))
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

func EnableKubernetes(path string) (bool){
	url := fmt.Sprintf("%s/v1/sys/auth/%s", public.VAULT_ADDR, path)

	st := make(map[string]interface{})
	st["type"] = "kubernetes"
	body, _ := json.Marshal(st)

	_, err := httpDo("POST", url, body, "X-Vault-Token", public.VAULT_TOKEN)
	if (err != nil){
		fmt.Printf("vault /v1/sys/auth/:path fail:%v\r\n", err)
		return false
	}
	return true
}

func ConfigKubernetes(path string, host string, ca string) (bool){
	url := fmt.Sprintf("%s/v1/auth/%s/config", public.VAULT_ADDR, path)

	st := make(map[string]interface{})
	st["kubernetes_host"] = host
	st["kubernetes_ca_cert"] = ca
	
	body, _ := json.Marshal(st)
	_, err := httpDo("POST", url, body, "X-Vault-Token", public.VAULT_TOKEN)
	if (err != nil){
		fmt.Printf("vault /v1/auth/:path/config fail:%v\r\n", err)
		return false
	}
	return true
}

func CreateVaultPath(path string) (bool){
	url := fmt.Sprintf("%s/v1/secret/data/%s", public.VAULT_ADDR, path)

	st := make(map[string]interface{})
	st["data"] = nil	
	
	body, _ := json.Marshal(st)	
	resp, err := httpDo("POST", url, body, "X-Vault-Token", public.VAULT_TOKEN)	

	if (err != nil) {		
		fmt.Printf("vault /v1/secret/data/:path resp body:%v\r\n", resp.Body)		
		return false		
	} else {
		if (resp.StatusCode != 200) {
			fmt.Printf("vault /v1/secret/data/:path resp body:%v\r\n", resp.Body)
			return false
		}
	}	
	bodyByte, err := ioutil.ReadAll(resp.Body)
	fmt.Println(string(bodyByte))	

	return true
}

func AddPolicy(name string, path string) (bool){
	url := fmt.Sprintf("%s/v1/sys/policies/acl/%s", public.VAULT_ADDR, name)

	st := make(map[string]interface{})
	policy := fmt.Sprintf("path \"secret/data/%s/*\" { \n capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]  \n}", path)
	st["policy"] = policy		
	body, _ := json.Marshal(st)
	
	resp, err := httpDo("PUT", url, body, "X-Vault-Token", public.VAULT_TOKEN)	
	if (err != nil) {
		fmt.Printf("vault /v1/sys/policies/acl/:name fail:%v\r\n", err)
		return false
	}
	bodyByte, err := ioutil.ReadAll(resp.Body)
	fmt.Println(string(bodyByte))	
	return true
}

func WriteSecrets(path string, data []byte, token string) (*http.Response, error){

	url := fmt.Sprintf("%s/v1/secret/data/%s", public.VAULT_ADDR, path)		
	return httpDo("POST", url, data, "X-Vault-Token", token)	
	
}