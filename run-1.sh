#! /bin/bash
################################################################################
# FILENAME:
#     test.sh
#
# DESCRIPTION:
#     This script is used to ...
#
# REVISION(MM/DD/YYYY):
#     03/21/2009  wh8199(wang.hui@advantech.com.cn)
#     - Initial version
################################################################################
secret=$(cat ./vault-secrets.txt)
echo "secret is: "
echo $secret
MP_TOKEN=$(cat ./vault-secrets.txt | sed 's/,/\n/g' | grep "MP_TOKEN"  | sed 's/"//g' | sed 's/ //g' | sed 's/MP_TOKEN://g')
MP_ADDR=$(cat ./vault-secrets.txt | sed 's/,/\n/g' | grep "MP_ADDR"  | sed 's/"//g' | sed 's/ //g'| sed 's/MP_ADDR://g')
VAULT_TOKEN=$(cat ./vault-secrets.txt | sed 's/,/\n/g' | grep "VAULT_TOKEN" | sed 's/"//g' | sed 's/ //g'| sed 's/VAULT_TOKEN://g')
VAULT_ADDR=$(cat ./vault-secrets.txt | sed 's/,/\n/g' | grep "VAULT_ADDR" |  sed 's/"//g' | sed 's/ //g'| sed 's/VAULT_ADDR://g')
export MP_TOKEN=$MP_TOKEN
export MP_ADDR=$MP_ADDR
export VAULT_TOKEN=$VAULT_TOKEN
export VAULT_ADDR=$VAULT_ADDR

echo  "***********************"
env
echo  "**********************"
#exec vault
