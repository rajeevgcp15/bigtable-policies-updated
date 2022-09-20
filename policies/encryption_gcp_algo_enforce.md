# Readme File for "encryption_gcp_algo_enforce.sentinel"

encryption_gcp_algo_enforce.sentinel

# Following rules have been evaluated"

|Rule|Description|
|----|-----|
|GCP_CAS_CAENTALG|CMEK Keys used for "enterprise" tier CAs must use one of the allowed encryption algorithms. Allowed algorithms are - ["RSA_SIGN_PSS_2048_SHA256", "RSA_SIGN_PSS_3072_SHA256", "RSA_SIGN_PSS_4096_SHA256", "RSA_SIGN_PKCS1_2048_SHA256", "RSA_SIGN_PKCS1_3072_SHA256", "RSA_SIGN_PKCS1_4096_SHA256"].|
|GCP_CAS_CADEVOPSALG|DEVOPS tier CAs must use one of the allowed algorithms (Google Managed encryption keys) -  ["RSA_PSS_2048_SHA256", "RSA_PSS_3072_SHA256", "RSA_PSS_4096_SHA256", "RSA_PKCS1_2048_SHA256", "RSA_PKCS1_3072_SHA256", "RSA_PKCS1_4096_SHA256"].|

## Imports 
```
import "tfstate-functions" as tfstate
import "tfconfig-functions" as tfconfig
import "tfstate/v2" as tfstate2
import "tfconfig/v2" as tfconfig2
import "tfplan-functions" as plan
import "strings"
import "types"
```
## code to gather details from tfplan and tfconfig and creating different type of maps for evaluation :

```
allCAPoolTfstateInstances = tfstate.find_resources("google_privateca_ca_pool")
allCAPoolTfplanInstances = plan.find_resources("google_privateca_ca_pool")
allCertAuthorityInstances = plan.find_resources("google_privateca_certificate_authority")
allCryptoKeyTfplanInstances = plan.find_resources("google_kms_crypto_key")

#=================function for tfstate ============================================
find_resources = func(type) {
	resources = filter tfstate2.resources as address, r {
		r.type is type
	}
	return resources
}

#=================function for tfconfig ============================================
find_resources_tfconfig = func(type) {
	resources = filter tfconfig2.resources as address, r {
		r.type is type
	}
	return resources
}

allCryptoKeyTfstateInstances = find_resources("google_kms_crypto_key")

caInstancesTfconfig = find_resources_tfconfig("google_privateca_certificate_authority")
cryptokeyVersionInstancesTfconfig = find_resources_tfconfig("google_kms_crypto_key_version")
cryptokeyInstancesTfconfig = find_resources_tfconfig("google_kms_crypto_key")

tfconfig_kms_key_version = {}
for cryptokeyVersionInstancesTfconfig as address, rc {
	crypto_key_ver_name = rc.name
	crypto_key_ref = rc.config.crypto_key.references[0]
	crypto_key_version_name = strings.split(crypto_key_ref, ".")
	tfconfig_kms_key_version[crypto_key_ver_name] = crypto_key_version_name[1]
}
//print("KMS_VERSION_CEYPTO_KEY_MAP:>>" + plan.to_string(tfconfig_kms_key_version))

tfconfig_ca = {}
for caInstancesTfconfig as address, rc {
	if length(caInstancesTfconfig) != 0 {
	ca_name = rc.config.certificate_authority_id.constant_value
	kms_key_version_tfconfig = tfconfig.evaluate_attribute(rc.config.key_spec[0], "cloud_kms_key_version")
	is_kms_key_version_undefined = rule {types.type_of(kms_key_version_tfconfig) is "undefined"}
	if not is_kms_key_version_undefined {
	cryptoKeyVersionTfconfig = strings.split(kms_key_version_tfconfig.references[0], ".")
    crypto_vers = cryptoKeyVersionTfconfig[2]
    cryptokey_name_tfcon = tfconfig_kms_key_version[crypto_vers]
    tfconfig_ca[ca_name] = cryptokey_name_tfcon
	}
	}
}

//print("CA-CRYPTOKEY-MAP:>>" + plan.to_string(tfconfig_ca))

tfconfig_cryptokey_algo = {}
for cryptokeyInstancesTfconfig as address, rc {
	crypto_name = rc.name
	crypto_algo_tfconfig = tfconfig.evaluate_attribute(rc.config, "version_template")
	is_crypto_algo_tfconfig_undefined = rule { types.type_of(crypto_algo_tfconfig) is "undefined"}
	if not is_crypto_algo_tfconfig_undefined {
         tfconfig_cryptokey_algo[crypto_name] = crypto_algo_tfconfig[0].algorithm.constant_value
	}
}

//print("CRYPTOKRY_ALGO_MAP:>>" + plan.to_string(tfconfig_cryptokey_algo))

tfconfig_cryptokey_protection = {}
for cryptokeyInstancesTfconfig as address, rc {
	crypto_name_pro = rc.name
	crypto_protection_tfconfig = tfconfig.evaluate_attribute(rc.config, "version_template")
	is_crypto_protection_tfconfig_undefined = rule {types.type_of(crypto_protection_tfconfig) is "undefined"}
	if not is_crypto_protection_tfconfig_undefined {
		protection = crypto_protection_tfconfig[0].protection_level.constant_value
	tfconfig_cryptokey_protection[crypto_name_pro] = protection
	}
}

//print("CRYPTOKRY_PROTECTION_MAP:>>" + plan.to_string(tfconfig_cryptokey_protection))

tfconfig_cryptokey_name_mapping = {}
for cryptokeyInstancesTfconfig as address, rc {
	crypto_name_tfcon = rc.name
	crypto_name_actual = rc.config.name.constant_value
	//print(crypto_name_actual)
	tfconfig_cryptokey_name_mapping[crypto_name_tfcon] = crypto_name_actual
}

//print("CRYPTOKRY_NAME_MAP:>>" + plan.to_string(tfconfig_cryptokey_name_mapping))

#===============================================================================================

array = {}
for allCAPoolTfstateInstances as address, rc {
	capoolname = tfstate.evaluate_attribute(rc, "name")
	capooltier = tfstate.evaluate_attribute(rc, "tier")
	array[capoolname] = capooltier
}

array2 = {}
for allCAPoolTfplanInstances as address, rc {
	cpool_name = plan.evaluate_attribute(rc, "name")
	cpool_tier = plan.evaluate_attribute(rc, "tier")
	array2[cpool_name] = cpool_tier

}
array_main = {}
for array as address, rc {
	array_main[address] = rc
}

for array2 as address, rc {
	array_main[address] = rc
}

allCryptoKeyTfstateInstances = find_resources("google_kms_crypto_key")

array_tfstate_cryptokey = {}
for allCryptoKeyTfstateInstances as address, rc {
	cryptokeyname = tfstate.evaluate_attribute(rc, "name")
	cryptokeyalgorithm = tfstate.evaluate_attribute(rc, "version_template.0.algorithm")
	array_tfstate_cryptokey[cryptokeyname] = cryptokeyalgorithm
}

array_tfplan_cryptokey = {}
for allCryptoKeyTfplanInstances as address, rc {
	crypto_plan_keyname = plan.evaluate_attribute(rc, "name")
	crypto_plan_key_algorithm = plan.evaluate_attribute(rc, "version_template.0.algorithm")
	array_tfplan_cryptokey[crypto_plan_keyname] = crypto_plan_key_algorithm
}

array_cryptokey_main = {}

for array_tfstate_cryptokey as address, rc {
	array_cryptokey_main[address] = rc
}
for array_tfplan_cryptokey as address, rc {
	array_cryptokey_main[address] = rc
}



```
##GCP_CAS_CAENTALG     : CMEK Keys used for "enterprise" tier CAs must use one of the allowed encryption algorithms. Allowed algorithms are - ["RSA_SIGN_PSS_2048_SHA256", "RSA_SIGN_PSS_3072_SHA256", "RSA_SIGN_PSS_4096_SHA256", "RSA_SIGN_PKCS1_2048_SHA256", "RSA_SIGN_PKCS1_3072_SHA256", "RSA_SIGN_PKCS1_4096_SHA256"].

```
b = 0
c = 0
messages_algorithm = {}
for allCertAuthorityInstances as address, rc {

	cert_pool_name = plan.evaluate_attribute(rc, "pool")
	a = array_main[cert_pool_name]
	b = a
	c = cert_pool_name

	if (not (types.type_of(b) is "undefined") and b == "ENTERPRISE") {
		kms_key_version = plan.evaluate_attribute(rc, "key_spec.0.cloud_kms_key_version")
		cmek_after_unknown = plan.evaluate_attribute(rc.change.after_unknown, "key_spec.0.cloud_kms_key_version")

		if (kms_key_version == null and cmek_after_unknown == null) {
			messages_algorithm[address] = rc
			print("kms key version undefined, Please specify key_spec.0.cloud_kms_key_version attribute for resource: " + address)
		} else {
			if cmek_after_unknown == true {
				ca_name = plan.evaluate_attribute(rc, "certificate_authority_id")
				crypto_key_id_name = tfconfig_ca[ca_name]
				cryptokey_algo_name = tfconfig_cryptokey_algo[crypto_key_id_name]
				if cryptokey_algo_name not in allowed_algorithm_crypto_vt {
					print("Please select algorithm from following allowed algorithm list for cryptokey: "+plan.to_string(tfconfig_cryptokey_name_mapping[crypto_key_id_name]) +".Allowed algorithms are: "+plan.to_string(allowed_algorithm_crypto_vt))
					messages_algorithm[address] = rc
				}

			} else {

				cryptoKeyName = strings.split(kms_key_version, "/")
				c_key_name = cryptoKeyName[7]
				x = array_cryptokey_main[c_key_name]
				is_x_undefined = rule { types.type_of(x) is "undefined" }

				if is_x_undefined {
					messages_algorithm[address] = rc
					print("Please use cryptokey with version template and Algorithm for Certificate Authority for resource:" + address)
				} else {
					if not (x in allowed_algorithm_crypto_vt) {
						print("Algorithm used to create " + c_key_name + " is not in Allowed Algorithm List")
						messages_algorithm[address] = rc
					}
				}
			}
		}

	} else {
		if (types.type_of(b) is "undefined") {
			messages = "CA Pool Tier Couldn't be Found"
			print("CA Pool Tier Couldn't be Found for pool for resource: " + address)
		}
	}
}

GCP_CAS_CAENTALG = rule { length(messages_algorithm) is 0 }

```
##GCP_CAS_CADEVOPSALG : DEVOPS tier CAs must use one of the allowed algorithms (Google Managed encryption keys) -  ["RSA_PSS_2048_SHA256", "RSA_PSS_3072_SHA256", "RSA_PSS_4096_SHA256", "RSA_PKCS1_2048_SHA256", "RSA_PKCS1_3072_SHA256", "RSA_PKCS1_4096_SHA256"]
```
#######################################################
####--------------DEVOPS RULE-----------------------###
#######################################################

messages_algorithm_devops = {}
for allCertAuthorityInstances as address, rc {
	cert_pool_name_devops = plan.evaluate_attribute(rc, "pool")
	a_devops = array_main[cert_pool_name_devops]

	if (not (types.type_of(a_devops) is "undefined") and a_devops == "DEVOPS") {

		ca_private_kms_algorithm = plan.evaluate_attribute(rc, "key_spec.0.algorithm")
		if (ca_private_kms_algorithm not in allowed_algorithms_ca_spec or types.type_of(ca_private_kms_algorithm) is "undefined" or types.type_of(ca_private_kms_algorithm) is "null" or length(ca_private_kms_algorithm) == 0) {
			messages_algorithm_devops[address] = rc
			print("Algorithm must be defined for resource :- " + address + " .Allowed algorithm are: ", allowed_algorithms_ca_spec)
		}
	} else {
		if (types.type_of(b) is "undefined") {
			messages = "CA Pool Tier Couldn't be Found"
			print("CA Pool Tier Couldn't be Found for pool for resource: " + address)
		}
	}
}

GCP_CAS_CADEVOPSALG = rule { length(messages_algorithm_devops) is 0 }
```


```

## The Main Function
This function returns "False" if length of all flag is not 0.

```

# Main rule
main = rule { GCP_CAS_CAENTALG and GCP_CAS_CADEVOPSALG }


```
