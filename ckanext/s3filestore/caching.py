import logging
from datetime import datetime, timezone

import boto3
from botocore.credentials import InstanceMetadataProvider, InstanceMetadataFetcher
from botocore.exceptions import BotoCoreError, ClientError

import ckan.plugins.toolkit as tk

from dogpile.cache import make_region
from ckanext.hdx_theme.helpers.caching import dogpile_standard_config, dogpile_config_filter

log = logging.getLogger(__name__)
config = tk.config

dogpile_aws_config = {
    'cache.redis.expiration_time': 60 * 55,  # 55 minutes, 5 minutes before credentials expire
}
dogpile_aws_config.update(dogpile_standard_config)

dogpile_aws_region = make_region(key_mangler=lambda key: 'aws-' + key)
dogpile_aws_region.configure_from_config(dogpile_aws_config, dogpile_config_filter)

# Load AWS configuration at module import time
# Note: This is intentional and safe because:
# 1. CKAN config is fully loaded before plugins are imported
# 2. These values don't change at runtime (require app restart)
# 3. Loading once at import avoids repeated config lookups on every request
role_name_or_arn = config.get('ckanext.s3filestore.aws_role_arn')
region = config.get('ckanext.s3filestore.region_name')
session_name = config.get('ckanext.s3filestore.aws_role_session_name', 'ckan-s3filestore-session')

# Debug logging
log.info('S3 Caching Config - role_arn: {0}, region: {1}, session_name: {2}'.format(
    role_name_or_arn, region, session_name))


class S3AssumeRoleException(Exception):
    """Exception raised when AssumeRole fails"""
    pass


def get_fresh_s3_credentials():
    """
    Get valid S3 credentials from cache or regenerate if expired/expiring.

    This function provides automatic credential refresh with a safety buffer:
    - First attempts to retrieve cached credentials from Redis
    - Validates expiration time has >5 minutes remaining
    - If expiring soon (<5 min), invalidates cache and generates fresh credentials
    - If valid (>5 min), returns cached credentials without AWS API call

    The 5-minute buffer ensures credentials remain valid during request processing,
    preventing race conditions where credentials expire mid-request.

    Flow:
    1. Call cached_load_s3filestore_credentials() (returns from cache if available)
    2. Check expiration time
    3. If <5 min remaining: invalidate cache + regenerate
    4. If >5 min remaining: return cached credentials
    5. Return valid credentials

    :return: Dict with keys: AccessKeyId, SecretAccessKey, SessionToken, Expiration
    :rtype: dict
    :raises S3AssumeRoleException: If credential loading/validation fails
    """

    # Get credentials (from cache or fresh)
    credentials = cached_load_s3filestore_credentials()

    # Check if credentials are still valid
    if credentials.get('Expiration'):
        expiration = credentials['Expiration']
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        time_until_expiry = expiration - now
        minutes_until_expiry = int(time_until_expiry.total_seconds() / 60)

        # If expiring in less than 5 minutes, invalidate cache and get fresh ones
        if time_until_expiry.total_seconds() < 300:  # 5 minutes
            log.warning('Credentials expiring in {0} minutes, invalidating cache and refreshing...'.format(
                minutes_until_expiry))
            cached_load_s3filestore_credentials.invalidate()
            credentials = cached_load_s3filestore_credentials()
        else:
            log.debug('Using cached credentials, valid for {0} more minutes'.format(minutes_until_expiry))

    return credentials


@dogpile_aws_region.cache_on_arguments()
def cached_load_s3filestore_credentials():
    """
    Load fresh S3 credentials via AssumeRole using EC2 instance metadata.
    Cached in Redis via dogpile - automatically reuses credentials if valid.

    Uses configuration from:
    - ckanext.s3filestore.aws_role_arn
    - ckanext.s3filestore.region_name
    - ckanext.s3filestore.aws_role_session_name

    :return: Dict with credentials (AccessKeyId, SecretAccessKey, SessionToken, Expiration)
    :raises S3AssumeRoleException: If credential loading fails
    """
    try:
        # Validate configuration
        if not role_name_or_arn:
            raise S3AssumeRoleException('Missing required config: ckanext.s3filestore.aws_role_arn')
        if not region:
            raise S3AssumeRoleException('Missing required config: ckanext.s3filestore.region_name')

        log.info('Loading fresh S3 filestore credentials via AssumeRole for role: {0}'.format(role_name_or_arn))

        # Create base session with explicit instance metadata provider
        fetcher = InstanceMetadataFetcher(timeout=1, num_attempts=2)
        provider = InstanceMetadataProvider(iam_role_fetcher=fetcher)

        # Get credentials from instance metadata
        instance_creds = provider.load()
        if instance_creds is None:
            raise S3AssumeRoleException('Failed to load credentials from EC2 instance metadata')

        # Create session with instance profile credentials
        base_session = boto3.Session(
            aws_access_key_id=instance_creds.access_key,
            aws_secret_access_key=instance_creds.secret_key,
            aws_session_token=instance_creds.token,
            region_name=region
        )

        sts_client = base_session.client('sts')

        # Check if role_arn is full ARN or just role name
        if role_name_or_arn.startswith('arn:aws:iam::'):
            full_role_arn = role_name_or_arn
        else:
            account_id = sts_client.get_caller_identity()['Account']
            full_role_arn = 'arn:aws:iam::{0}:role/{1}'.format(account_id, role_name_or_arn)

        log.info('Assuming role with ARN: {0}'.format(full_role_arn))
        log.info('Using session name: {0}'.format(session_name))
        log.info('Using region: {0}'.format(region))

        # Assume role with 1 hour duration (credentials valid for 60 minutes)
        # Cache TTL is 55 minutes, so cached credentials are only used for 55 minutes
        # and are refreshed 5 minutes before they actually expire
        assumed_role = sts_client.assume_role(
            RoleArn=full_role_arn,
            RoleSessionName=session_name,
            DurationSeconds=3600  # 60 minutes = 3600 seconds
        )

        # Extract credentials
        credentials = {
            'AccessKeyId': assumed_role['Credentials']['AccessKeyId'],
            'SecretAccessKey': assumed_role['Credentials']['SecretAccessKey'],
            'SessionToken': assumed_role['Credentials']['SessionToken'],
            'Expiration': assumed_role['Credentials']['Expiration']
        }

        # Ensure expiration is timezone-aware
        if credentials['Expiration'].tzinfo is None:
            credentials['Expiration'] = credentials['Expiration'].replace(tzinfo=timezone.utc)

        # Calculate time until expiration
        now = datetime.now(timezone.utc)
        time_until_expiry = credentials['Expiration'] - now
        minutes_until_expiry = int(time_until_expiry.total_seconds() / 60)

        log.info('Successfully loaded S3 credentials, expire at: {0} (in {1} minutes)'.format(
            credentials['Expiration'].strftime('%Y-%m-%d %H:%M:%S UTC'),
            minutes_until_expiry))

        return credentials

    except S3AssumeRoleException:
        raise
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        log.error('AWS API error during AssumeRole: {0} - {1}'.format(error_code, error_msg))
        raise S3AssumeRoleException('AWS API error: {0} - {1}'.format(error_code, error_msg))
    except BotoCoreError as e:
        log.error('Boto core error loading credentials: {0}'.format(str(e)))
        raise S3AssumeRoleException('Boto error: {0}'.format(str(e)))
    except Exception as e:
        # Catch-all for unexpected errors (e.g., network issues, serialization problems)
        log.error('Unexpected error loading S3 credentials: {0}'.format(str(e)), exc_info=True)
        raise S3AssumeRoleException('Unexpected error: {0}'.format(str(e)))
