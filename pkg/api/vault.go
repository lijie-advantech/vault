package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/vault/vault/pkg/model"
	"github.com/vault/vault/pkg/public"
)

// ListSecrets godoc
// @Summary
// @Description
// @Accept  json
// @Produce  json
// @Param clusterName path string true "Cluster Name"
// @Param namespaceName path string true "Namespace Name"
// @Param path path string true "Secret Path"
// @Success 200 {object} model.Secret
// @Failure 500 {object} model.APIError
// @Router /clusterName/{clusterName}/namespaceName/{namespaceName}/{path} [get]
func ListSecrets(c *gin.Context) {
	vaultRootToken, err := public.GetVaultRootToken()
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}

	mpToken := c.Request.Header["Authorization"][0][7:]
	clusterName := c.Param("clusterName")
	namespaceName := c.Param("namespaceName")
	path := c.Param("path")

	jwtToken, err := GetDefaultSecretToken(clusterName, namespaceName, mpToken)
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}

	token, err := LoginWithK8s(clusterName, namespaceName, jwtToken, vaultRootToken)
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}

	secretPath := fmt.Sprintf("clusterName/%s/namespaceName/%s/%s", clusterName,
		namespaceName, path)
	resp, err := ReadSecrets(secretPath, token)
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}
	bodyByte, err := ioutil.ReadAll(resp.Body)
	body := &model.Secret{}
	json.Unmarshal(bodyByte, &body)
	c.JSON(resp.StatusCode, body)

}

// ListSecretKeys godoc
// @Summary
// @Description
// @Accept  json
// @Produce  json
// @Param clusterName path string true "Cluster Name"
// @Param namespaceName path string true "Namespace Name"
// @Success 200 {object} model.Secret
// @Failure 500 {object} model.APIError
// @Router /clusterName/{clusterName}/namespaceName/{namespaceName} [get]
func ListSecretKeys(c *gin.Context) {
	vaultRootToken, err := public.GetVaultRootToken()
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}

	clusterName := c.Param("clusterName")
	namespaceName := c.Param("namespaceName")

	secretPath := fmt.Sprintf("clusterName/%s/namespaceName/%s", clusterName, namespaceName)
	resp, err := ReadSecretKeys(secretPath, vaultRootToken)
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}
	defer resp.Body.Close()
	bodyByte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}
	body := &model.Secret{}
	json.Unmarshal(bodyByte, &body)
	c.JSON(resp.StatusCode, body)

}

// EnableVault godoc
// @Summary
// @Description
// @Accept  json
// @Produce  json
// @Param clusterName path string true "Cluster Name"
// @Param namespaceName path string true "Namespace Name"
// @Success 200 {object} model.APISuccess
// @Failure 500 {object} model.APIError
// @Router /clusterName/{clusterName}/namespaceName/{namespaceName} [post]
func EnableVault(c *gin.Context) {
	vaultRootToken, err := public.GetVaultRootToken()
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
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
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}
	err = AddPolicy(policyName, dataPath, vaultRootToken)
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}

	err = CreateRole(kubernetesPath, roleName, saName, saNamespace, policyName, vaultRootToken)
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}
	c.JSON(200, model.APISuccess{Message: "success"})
}

// CreateSecrets godoc
// @Summary
// @Description
// @Accept  json
// @Produce  json
// @Param clusterName path string true "Cluster Name"
// @Param namespaceName path string true "Namespace Name"
// @Param path path string true "Secret Path"
// @Success 200 {object} model.Secret
// @Failure 500 {object} model.APIError
// @Router /clusterName/{clusterName}/namespaceName/{namespaceName}/{path} [post]
func CreateSecrets(c *gin.Context) {
	vaultRootToken, err := public.GetVaultRootToken()
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}

	mpToken := c.Request.Header["Authorization"][0][7:]
	clusterName := c.Param("clusterName")
	namespaceName := c.Param("namespaceName")
	path := c.Param("path")

	jwtToken, err := GetDefaultSecretToken(clusterName, namespaceName, mpToken)
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}

	token, err := LoginWithK8s(clusterName, namespaceName, jwtToken, vaultRootToken)
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}
	logrus.Info("Vault token is ", token)

	secretPath := fmt.Sprintf("clusterName/%s/namespaceName/%s/%s", clusterName,
		namespaceName, path)
	buf := make([]byte, 1024)
	n, _ := c.Request.Body.Read(buf)
	resp, err := WriteSecrets(secretPath, buf[0:n], token)
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}
	bodyByte, err := ioutil.ReadAll(resp.Body)
	bodyJson := &model.Secret{}
	json.Unmarshal(bodyByte, &bodyJson)
	c.JSON(resp.StatusCode, bodyJson)

}

// InjectSidecar godoc
// @Summary
// @Description
// @Accept  json
// @Produce  json
// @Param clusterName path string true "Cluster Name"
// @Param namespaceName path string true "Namespace Name"
// @Param deploymentName path string true "Deployment Name"
// @Success 200 {object} model.APISuccess
// @Failure 500 {object} model.APIError
// @Router /clusterName/{clusterName}/namespaceName/{namespaceName}/deploymentName/{deploymentName} [put]
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
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}

	err = AddDeploymentLabel(clusterName, namespaceName, deploymentName, mpToken)
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}

	err = DeleteDeploymentPod(clusterName, namespaceName, deploymentName, mpToken)
	if err != nil {
		c.JSON(500, model.APIError{ErrorMessage: err.Error()})
		return
	}
	c.JSON(200, model.APISuccess{Message: "success"})

}
