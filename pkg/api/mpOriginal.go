package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func GetDefaultSecretToken(clusterName string, namespaceName string,
	mpToken string) (string, error) {
	//get secret token
	var jwtToken string
	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/secrets",
		os.Getenv("MP_ADDR"), clusterName, namespaceName)
	respSec, err := httpDo("GET", mpUrl, nil, "Authorization", mpToken)
	if err != nil {
		logrus.Error(mpUrl, err)
		return "", err
	}
	defer respSec.Body.Close()
	respBodySec, err := ioutil.ReadAll(respSec.Body)
	if err != nil {
		return "", err
	}
	if respSec.StatusCode != 200 {
		logrus.Error(mpUrl, string(respBodySec))
		return "", errors.New(gjson.GetBytes(respBodySec, "reason").String())
	}

	result := gjson.GetBytes(respBodySec, "items")
	for _, name := range result.Array() {
		secretName := gjson.Get(name.String(), "metadata.name")
		logrus.Info("secret name is ", secretName)
		if strings.Contains(secretName.String(), "default-token") {
			jwtStr := gjson.Get(name.String(), "data.token")
			jwtBase64, _ := base64.StdEncoding.DecodeString(jwtStr.String())
			jwtToken = string(jwtBase64)
		}
	}
	logrus.Info("Jwt token is ", jwtToken)
	return jwtToken, nil
}

func CreateConfigmap(clusterName string, namespaceName string, deploymentName string,
	kubernetesPath string, template string, mpToken string) error {

	configmapName := deploymentName + "-vault-configmap"
	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/configmap/%s",
		os.Getenv("MP_ADDR"), clusterName, namespaceName, configmapName)
	resp, err := httpDo("DELETE", mpUrl, nil, "Authorization", mpToken)
	if err != nil {
		logrus.Error(mpUrl, err)
		return err
	}
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		respByte, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		logrus.Error(mpUrl, string(respByte))
		return errors.New(gjson.GetBytes(respByte, "reason").String())
	}

	roleName := fmt.Sprintf("clusterName_%s_namespaceName_%s", clusterName, namespaceName)
	curDir, err := os.Getwd()
	if err != nil {
		return err
	}
	vacofByte, err := ioutil.ReadFile(curDir + "/template/vault-agent-config.hcl")
	if err != nil {
		logrus.Error(err)
		return err
	}
	vaconfStr := strings.Replace(string(vacofByte), "VAULT_ROLE", roleName, -1)
	vaconfStr = strings.Replace(vaconfStr, "KUBERNETES_PATH", kubernetesPath, -1)

	ctconfByte, err := ioutil.ReadFile(curDir + "/template/consul-template-config.hcl")
	if err != nil {
		logrus.Error(err)
		return err
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

	body, err := json.Marshal(st)
	if err != nil {
		return err
	}

	mpUrl = fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/configmap",
		os.Getenv("MP_ADDR"), clusterName, namespaceName)

	resp, err = httpDo("POST", mpUrl, body, "Authorization", mpToken)
	if err != nil {
		logrus.Error(mpUrl, err)
		return err
	}
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		respByte, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		logrus.Error(mpUrl, string(respByte))
		return errors.New(gjson.GetBytes(respByte, "reason").String())
	}
	return nil

}

func DeletePod(clusterName string, namespaceName string, podName string, mpToken string) error {

	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/pod/%s",
		os.Getenv("MP_ADDR"), clusterName, namespaceName, podName)

	resp, err := httpDo("DELETE", mpUrl, nil, "Authorization", mpToken)
	if err != nil {
		logrus.Error(mpUrl, err)
		return err
	}
	if resp.StatusCode != 200 {
		respByte, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		logrus.Error(mpUrl, string(respByte))
		return errors.New(gjson.GetBytes(respByte, "reason").String())
	}
	return nil
}

func AddDeploymentLabel(clusterName string, namespaceName string, deploymentName string,
	mpToken string) error {

	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/deployment/%s",
		os.Getenv("MP_ADDR"), clusterName, namespaceName, deploymentName)
	//get deployment
	respDeploy, err := httpDo("GET", mpUrl, nil, "Authorization", mpToken)
	if err != nil {
		logrus.Error(mpUrl, err)
		return err
	}
	defer respDeploy.Body.Close()
	deployByte, err := ioutil.ReadAll(respDeploy.Body)
	if err != nil {
		return err
	}
	if respDeploy.StatusCode != 200 {
		logrus.Error(mpUrl, string(deployByte))
		return errors.New(gjson.GetBytes(deployByte, "reason").String())
	}

	//set label in deployment
	outDeployByte, err := sjson.SetBytes(deployByte, "spec.template.metadata.labels.vault-inject", "true")
	if err != nil {
		return err
	}
	//add label in deployment
	resp, err := httpDo("PUT", mpUrl, outDeployByte, "Authorization", mpToken)
	if err != nil {
		logrus.Error(mpUrl, err)
		return err
	}
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		respByte, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		logrus.Error(mpUrl, string(respByte))
		return errors.New(gjson.GetBytes(respByte, "reason").String())
	}
	return nil
}

func DeleteDeploymentPod(clusterName string, namespaceName string, deploymentName string,
	mpToken string) error {
	//get pods from deployment
	mpUrl := fmt.Sprintf("%s/v1/datacenter/cluster/%s/namespace/%s/deploymentpods/%s",
		os.Getenv("MP_ADDR"), clusterName, namespaceName, deploymentName)
	respPod, err := httpDo("GET", mpUrl, nil, "Authorization", mpToken)
	if err != nil {
		logrus.Error(mpUrl, err)
		return err
	}
	defer respPod.Body.Close()
	podByte, err := ioutil.ReadAll(respPod.Body)
	if err != nil {
		return err
	}
	if respPod.StatusCode != 200 {
		logrus.Error(mpUrl, string(podByte))
		return errors.New(gjson.GetBytes(podByte, "reason").String())
	}

	result := gjson.GetBytes(podByte, "#.metadata.name")
	for _, name := range result.Array() {
		logrus.Info("pod name is ", name.String())
		if DeletePod(clusterName, namespaceName, name.String(), mpToken) != nil {
			return err
		}
	}
	return nil
}
