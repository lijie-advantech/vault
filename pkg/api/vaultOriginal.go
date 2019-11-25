package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

func Login(path string, role string, jwt string, vaultRootToken string) (*http.Response, error) {
	url := fmt.Sprintf("%s/v1/auth/%s/login", os.Getenv("VAULT_ADDR"), path)

	st := make(map[string]interface{})
	st["role"] = role
	st["jwt"] = jwt
	body, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}

	return httpDo("POST", url, body, "X-Vault-Token", vaultRootToken)

}

func CreateRole(path string, name string, saName string, saNamespace string,
	policyName string, vaultRootToken string) (error) {
	url := fmt.Sprintf("%s/v1/auth/%s/role/%s", os.Getenv("VAULT_ADDR"), path, name)

	st := make(map[string]interface{})
	st["bound_service_account_names"] = saName
	st["bound_service_account_namespaces"] = saNamespace
	arr := []string{policyName}
	st["policies"] = arr

	body, err := json.Marshal(st)
	if err != nil {
		return err
	}
	resp, err := httpDo("POST", url, body, "X-Vault-Token", vaultRootToken)
	if err != nil {
		logrus.Error(url, err)
		return err
	}

	defer resp.Body.Close()
	bodyByte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	logrus.Info(string(bodyByte))

	return nil

}



func CreateVaultPath(path string, vaultRootToken string) (error) {
	url := fmt.Sprintf("%s/v1/secret/data/%s", os.Getenv("VAULT_ADDR"), path)

	st := make(map[string]interface{})
	st["data"] = nil

	body, err := json.Marshal(st)
	if err != nil {
		return err
	}

	resp, err := httpDo("POST", url, body, "X-Vault-Token", vaultRootToken)
	if err != nil {
		logrus.Error(url, err)
		return err
	}
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		bodyByte, err := ioutil.ReadAll(resp.Body)
		logrus.Error(url, bodyByte)
		if err != nil {
			return err
		}
		return errors.New(gjson.GetBytes(bodyByte, "errors").String())
	}

	return nil
}

func AddPolicy(name string, path string, vaultRootToken string) (error) {
	url := fmt.Sprintf("%s/v1/sys/policies/acl/%s", os.Getenv("VAULT_ADDR"), name)

	st := make(map[string]interface{})
	policy := fmt.Sprintf("path \"secret/data/%s/*\" { \n capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]  \n}", path)
	st["policy"] = policy
	body, err := json.Marshal(st)
	if (err != nil) {
		return err
	}

	resp, err := httpDo("PUT", url, body, "X-Vault-Token", vaultRootToken)
	if err != nil {
		logrus.Error(url, err)
		return err
	}
	defer resp.Body.Close()
	bodyByte, err := ioutil.ReadAll(resp.Body)
	logrus.Info(string(bodyByte))
	return nil
}

func WriteSecrets(path string, data []byte, token string) (*http.Response, error) {

	url := fmt.Sprintf("%s/v1/secret/data/%s", os.Getenv("VAULT_ADDR"), path)
	return httpDo("POST", url, data, "X-Vault-Token", token)

}

func ReadSecretKeys(path string, token string) (*http.Response, error) {

	url := fmt.Sprintf("%s/v1/secret/metadata/%s/?list=true", os.Getenv("VAULT_ADDR"), path)
	return httpDo("GET", url, nil, "X-Vault-Token", token)

}

func ReadSecrets(path string, token string) (*http.Response, error) {

	url := fmt.Sprintf("%s/v1/secret/data/%s", os.Getenv("VAULT_ADDR"), path)
	return httpDo("GET", url, nil, "X-Vault-Token", token)

}

func LoginWithK8s(clusterName string, namespaceName string, jwtToken string,
	vaultRootToken string) (string, error) {
	roleName := fmt.Sprintf("clusterName_%s_namespaceName_%s", clusterName, namespaceName)
	kubernetesPath := "kubernetes-" + clusterName
	respLogin, err := Login(kubernetesPath, roleName, jwtToken, vaultRootToken)
	if err != nil {
		logrus.Error(err)
		return "", err
	}
	defer respLogin.Body.Close()
	bodyByteLogin, err := ioutil.ReadAll(respLogin.Body)
	logrus.Info(string(bodyByteLogin))
	token := gjson.GetBytes(bodyByteLogin, "auth.client_token").String()
	return token, nil
}
