terraform {
  required_providers {
    tfe = {
      source  = "hashicorp/tfe"
      version = "0.42.0"
    }
  }
}

provider "tfe" {
  hostname = var.hostname
}

module "agent_pool_ws" {
  source  = "alexbasista/workspacer/tfe"
  version = "0.7.0"

  organization   = var.org
  workspace_name = "tst-agent-1"
  execution_mode = "agent"
  agent_pool_id  = var.agent_pool_id
}

data "tfe_ssh_key" "tst" {
    organization = var.org
    name         = var.ssh_key_name 
}

module "ssh_key_ws" {
  source  = "alexbasista/workspacer/tfe"
  version = "0.7.0"

  organization   = var.org
  workspace_name = "tst-ssh-1"
  ssh_key_id     = data.tfe_ssh_key.tst.id
}

module "latest_tf_version_ws" {
  source  = "alexbasista/workspacer/tfe"
  version = "0.7.0"

  organization      = var.org
  workspace_name    = "tst-latest-tf-version-1"
  terraform_version = "latest" 
}

module "notification_ws" {
  source  = "alexbasista/workspacer/tfe"
  version = "0.7.0"

  organization      = var.org
  workspace_name    = "tst-nc-1"
  
  notifications = [
    {
        name             = "tst-generic"
        destination_type = "generic"
        url              = "https://example.com"
        token            = "abcdefg123456789"
        triggers         = ["run:completed", "run:errored"]
        enabled          = true
    },
    {
        name             = "tst-email"
        destination_type = "email"
        email_user_ids   = ["abasista"]
        triggers         = ["run:needs_attention"]
        enabled          = true
    }
  ]
}

module "vcs_ws" {
  source  = "alexbasista/workspacer/tfe"
  version = "0.7.0"

  organization      = var.org
  workspace_name    = "tst-vcs-1"
  auto_apply        = true 

  vcs_repo = {
    identifier     = "alexbasista/tfe-workspace-harness"
    oauth_token_id = var.oauth_token_id
  }
}

