provider "aws" {
  alias  = "dr"
  region = var.replica_region
}