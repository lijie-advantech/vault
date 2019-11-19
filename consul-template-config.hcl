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
  CONSUL_TEMPLATE  
  EOH
}