module "tfplan-functions" {
    source = "../../../common-functions/tfplan-functions/tfplan-functions.sentinel"
}

mock "tfplan/v2" {
  module {
    source = "mock-tfplan-v2-apigee-instance-location-pass-2.sentinel"
  }
}


test {
  rules = {
    main = true
  }
}