#!/usr/bin/python3.11

import os

from oci import Signer
from oci.config import from_file, get_config_value_or_default, DEFAULT_LOCATION, DEFAULT_PROFILE
from oci.auth import signers

# Globals
AUTH_PROFILE = 'profile'
AUTH_INSTANCE_PRINCIPAL = 'instance_principal'
AUTH_RESOURCE_PRINCIPAL = 'resource_principal'
AUTH_WORKLOAD_PRINCIPAL = 'workload_principal'
AUTH_DELEGATION_TOKEN = 'delegation_token'


class Authpy:
    """Authpy creates and returns authentication dictionaries and Signers for
       authentication to OCI.

       Attributes:
       profile - OCI profile name
       location - OCI configuration file location
    """

    def __init__(self, profile: str, location: str) -> tuple[dict, Signer]:
        self.profile = profile
        self.location = location

    # Signer entrypoint, fan out from here based on auth_type
    def create_signer(self, auth_type: str) -> tuple[dict, Signer]:
        func = {
            AUTH_PROFILE: self.create_profile_signer,
            AUTH_INSTANCE_PRINCIPAL: self.create_instance_principal_signer,
            AUTH_DELEGATION_TOKEN: self.create_delegation_token_signer,
            AUTH_WORKLOAD_PRINCIPAL: self.create_workload_principal_signer,
            AUTH_RESOURCE_PRINCIPAL: self.create_resource_principal
        }

        try:
            signer_func = func[auth_type]
            return signer_func()
        except KeyError:
            raise AuthException('Invalid authentication type')

    # Default profile signer
    def create_profile_signer(self) -> tuple[dict, Signer]:
        config = from_file(file_location=self.location, profile_name=self.profile)
        signer = Signer(
            tenancy=config["tenancy"],
            user=config["user"],
            fingerprint=config["fingerprint"],
            private_key_file_location=config.get("key_file"),
            pass_phrase=get_config_value_or_default(config, "pass_phrase"),
            private_key_content=config.get("key_content")
        )
        return config, signer

    # Signer for instance principal authentication within OCI
    def create_instance_principal_signer(self):
        try:
            signer = signers.InstancePrincipalsSecurityTokenSigner()
            cfg = {'region': signer.region, 'tenancy': signer.tenancy_id}
            return cfg, signer
        
        except Exception as e:
            raise AuthException(e)

    # Cloud Shell signer
    def create_delegation_token_signer(self) -> tuple[dict, Signer]:
        try:
            # Environment variables present in OCI Cloud Shell
            env_config_file = os.getenv('OCI_CONFIG_FILE')
            env_config_section = os.getenv('OCI_CONFIG_PROFILE')

            if not env_config_file or not env_config_section:
                raise AuthException(
                    'Required environment variables for delgation not found')

            config = from_file(env_config_file, env_config_section)
            delegation_token_location = config["delegation_token_file"]

            with open(delegation_token_location, 'r') as delegation_token_file:
                delegation_token = delegation_token_file.read().strip()
                signer = signers.InstancePrincipalsDelegationTokenSigner(delegation_token=delegation_token)

                return config, signer
        except Exception as e:
            raise AuthException(str(e))
        
    # Workload identity signer for use by Oracle Kubernetes Engine
    def create_workload_principal_signer(self) -> tuple[dict, Signer]:
        try:
            signer = signers.get_oke_workload_identity_resource_principal_signer()
            cfg = {'region': signer.region, 'tenancy': signer.tenancy_id}
            return cfg, signer
        except Exception as e:
            raise AuthException(str(e))
        
    # Serverless function signer
    def create_resource_principal(self) -> tuple[dict, Signer]:
        signer = signers.get_resource_principals_signer()
        cfg = {
            'region': signer.region,
            'tenancy': signer.tenancy_id
            }
            
        return cfg, signer
    

class AuthException(Exception):
    """Exception raised when an error occurs while retriving authentication
       configurations.
    """

    def __init__(self, error: str):
        self.error = error
        super().__init__(self.error)

    def __str__(self):
        return f'AuthException: {self.error}'
    

# make_signer is the convenience function to return signers without needing to
# engage Authpy class.
def make_signer(authentication_type: str,
                profile=DEFAULT_PROFILE,
                location=DEFAULT_LOCATION,
                *args, **kwargs) -> tuple[dict, Signer]:
    
    authpy = Authpy(profile, location)

    return authpy.create_signer(authentication_type)