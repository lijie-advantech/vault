vault {
  renew_token = false
  vault_agent_token_file = "/home/vault/.vault-token"
  retry {
    backoff = "1s"
  }
}

template {
  destination = "/etc/secrets/vault-secrets.txt"
  contents = <<EOH
  {{- with secret "secret/data/root" }}
  {
    "MP_TOKEN": "{{ .Data.data.MP_TOKEN }}",
    "MP_ADDR": "{{ .Data.data.MP_ADDR }}",
    "VAULT_TOKEN": "{{ .Data.data.VAULT_TOKEN }}",
    "VAULT_ADDR": "{{ .Data.data.VAULT_ADDR }}"
  }
  {{ end }}
  EOH
}
