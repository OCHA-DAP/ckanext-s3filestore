import logging

import ckan.plugins.toolkit as tk

from ckanext.hdx_theme.helpers.aws_credentials import (
    AwsAssumeRoleException,
    get_cached_aws_credentials,
)

log = logging.getLogger(__name__)
config = tk.config

# Load S3 configuration at module import time.
# CKAN config is fully loaded before plugins are imported, so this is safe.
role_name_or_arn = config.get('ckanext.s3filestore.aws_role_arn')
region = config.get('ckanext.s3filestore.region_name')
session_name = config.get(
    'ckanext.s3filestore.aws_role_session_name', 'ckan-s3filestore-session'
)

log.info('S3 credentials config - role_arn: %s, region: %s, session_name: %s',
         role_name_or_arn, region, session_name)


def get_cached_s3_credentials():
    """
    Return temporary S3 credentials via AssumeRole, cached in Redis via dogpile.

    Thin wrapper around ``get_cached_aws_credentials`` from ckanext-hdx_theme.
    Reads S3-specific config (``ckanext.s3filestore.*``) and delegates caching
    to the shared dogpile region in hdx_theme.

    :return: Dict with keys access_key, secret_key, session_token, expiration, region
    :raises AwsAssumeRoleException: If credential loading or config validation fails
    """
    if not role_name_or_arn:
        raise AwsAssumeRoleException(
            'Missing required config: ckanext.s3filestore.aws_role_arn'
        )
    if not region:
        raise AwsAssumeRoleException(
            'Missing required config: ckanext.s3filestore.region_name'
        )

    return get_cached_aws_credentials(role_name_or_arn, region, session_name)
