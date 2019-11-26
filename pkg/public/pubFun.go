package public

import (
	"errors"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"io/ioutil"
	"os"
)

func GetVaultRootToken() (string, error) {
	curDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	bytes, err := ioutil.ReadFile(curDir + "/secrets/vault-secrets.txt")
	logrus.Info("Read vault-secrets.txt content is ", string(bytes))
	if err != nil {
		logrus.Error(err)
		return "", err
	}
	token := gjson.GetBytes(bytes, "VAULT_TOKEN").String()
	if token == "" {
		return "", errors.New("Get vault root token is empty")
	}
	logrus.Info("Vault root token is ", token)
	return token, nil
}
