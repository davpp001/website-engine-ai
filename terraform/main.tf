# Terraform für IONOS Cloud Server

provider "ionoscloud" {
  token = var.ionos_token
}

resource "ionoscloud_datacenter" "wp_dc" {
  name = "wp-datacenter"
  location = "de/fra"
}

resource "ionoscloud_server" "wp_server" {
  datacenter_id = ionoscloud_datacenter.wp_dc.id
  name          = "wp-server"
  cores         = 2
  ram           = 4096
  cpu_family    = "AMD_OPTERON"
  availability_zone = "AUTO"
}

resource "ionoscloud_volume" "wp_volume" {
  datacenter_id = ionoscloud_datacenter.wp_dc.id
  name          = "wp-volume"
  size          = 80
  image         = "ubuntu:22.04"
  type          = "HDD"
  ssh_keys      = [file(var.ssh_key_path)]
}

resource "ionoscloud_nic" "wp_nic" {
  datacenter_id = ionoscloud_datacenter.wp_dc.id
  server_id     = ionoscloud_server.wp_server.id
  lan           = 1
  dhcp          = true
}

variable "ionos_token" {}
variable "ssh_key_path" {}
