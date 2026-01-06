# -*- coding: utf-8 -*-
"""
Unit tests for cached_load_s3filestore_credentials().

Tests verify:
1. AssumeRole using EC2 instance metadata
2. Correct credential format returned
3. Error handling for various failure scenarios
4. Dogpile caching behavior
"""
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from ckanext.s3filestore.caching import get_fresh_s3_credentials, cached_load_s3filestore_credentials, S3AssumeRoleException, dogpile_aws_region


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear dogpile cache before and after each test."""
    dogpile_aws_region.invalidate()
    yield
    dogpile_aws_region.invalidate()


@mock.patch('ckanext.s3filestore.caching.role_name_or_arn', 'arn:aws:iam::123456789012:role/TestRole')
@mock.patch('ckanext.s3filestore.caching.region', 'us-east-1')
@mock.patch('ckanext.s3filestore.caching.session_name', 'test-session')
@mock.patch('ckanext.s3filestore.caching.InstanceMetadataProvider')
@mock.patch('ckanext.s3filestore.caching.InstanceMetadataFetcher')
@mock.patch('ckanext.s3filestore.caching.boto3.Session')
def test_successful_assume_role(mock_session_class, mock_fetcher_class, mock_provider_class):
    """Test successful AssumeRole with full ARN."""
    # Mock instance metadata credentials
    mock_creds = mock.Mock()
    mock_creds.access_key = 'MOCK_ACCESS_KEY'
    mock_creds.secret_key = 'MOCK_SECRET_KEY'
    mock_creds.token = 'MOCK_TOKEN'

    mock_provider = mock.Mock()
    mock_provider.load.return_value = mock_creds
    mock_provider_class.return_value = mock_provider

    # Mock STS client
    expiration_time = datetime.now(timezone.utc) + timedelta(hours=1)
    mock_sts = mock.Mock()
    mock_sts.assume_role.return_value = {
        'Credentials': {
            'AccessKeyId': 'ASSUMED_KEY',
            'SecretAccessKey': 'ASSUMED_SECRET',
            'SessionToken': 'ASSUMED_TOKEN',
            'Expiration': expiration_time
        }
    }

    mock_session = mock.Mock()
    mock_session.client.return_value = mock_sts
    mock_session_class.return_value = mock_session

    # Call function - config mocked above
    credentials = cached_load_s3filestore_credentials()

    # Verify credentials returned correctly
    assert credentials['AccessKeyId'] == 'ASSUMED_KEY'
    assert credentials['SecretAccessKey'] == 'ASSUMED_SECRET'
    assert credentials['SessionToken'] == 'ASSUMED_TOKEN'
    assert 'Expiration' in credentials

    # Verify instance metadata was used
    mock_fetcher_class.assert_called_once_with(timeout=1, num_attempts=2)
    mock_provider.load.assert_called_once()

    # Verify assume_role was called with correct ARN
    mock_sts.assume_role.assert_called_once_with(
        RoleArn='arn:aws:iam::123456789012:role/TestRole',
        RoleSessionName='test-session'
    )


@mock.patch('ckanext.s3filestore.caching.role_name_or_arn', 'TestRole')
@mock.patch('ckanext.s3filestore.caching.region', 'us-east-1')
@mock.patch('ckanext.s3filestore.caching.session_name', 'test-session')
@mock.patch('ckanext.s3filestore.caching.InstanceMetadataProvider')
@mock.patch('ckanext.s3filestore.caching.InstanceMetadataFetcher')
@mock.patch('ckanext.s3filestore.caching.boto3.Session')
def test_assume_role_with_role_name(mock_session_class, mock_fetcher_class, mock_provider_class):
    """Test AssumeRole when given role name instead of full ARN."""
    # Mock instance metadata credentials
    mock_creds = mock.Mock()
    mock_creds.access_key = 'MOCK_ACCESS_KEY'
    mock_creds.secret_key = 'MOCK_SECRET_KEY'
    mock_creds.token = 'MOCK_TOKEN'

    mock_provider = mock.Mock()
    mock_provider.load.return_value = mock_creds
    mock_provider_class.return_value = mock_provider

    # Mock STS client
    expiration_time = datetime.now(timezone.utc) + timedelta(hours=1)
    mock_sts = mock.Mock()
    mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
    mock_sts.assume_role.return_value = {
        'Credentials': {
            'AccessKeyId': 'ASSUMED_KEY',
            'SecretAccessKey': 'ASSUMED_SECRET',
            'SessionToken': 'ASSUMED_TOKEN',
            'Expiration': expiration_time
        }
    }

    mock_session = mock.Mock()
    mock_session.client.return_value = mock_sts
    mock_session_class.return_value = mock_session

    # Call function - config mocked above
    credentials = cached_load_s3filestore_credentials()

    # Verify credentials returned correctly
    assert credentials['AccessKeyId'] == 'ASSUMED_KEY'

    # Verify get_caller_identity was called to get account ID
    mock_sts.get_caller_identity.assert_called_once()

    # Verify assume_role was called with constructed ARN
    mock_sts.assume_role.assert_called_once_with(
        RoleArn='arn:aws:iam::123456789012:role/TestRole',
        RoleSessionName='test-session'
    )


@mock.patch('ckanext.s3filestore.caching.role_name_or_arn', 'TestRole')
@mock.patch('ckanext.s3filestore.caching.region', 'us-east-1')
@mock.patch('ckanext.s3filestore.caching.session_name', 'test-session')
@mock.patch('ckanext.s3filestore.caching.InstanceMetadataProvider')
@mock.patch('ckanext.s3filestore.caching.InstanceMetadataFetcher')
def test_instance_metadata_failure(mock_fetcher_class, mock_provider_class):
    """Test error handling when instance metadata is unavailable."""
    # Mock instance metadata provider returning None
    mock_provider = mock.Mock()
    mock_provider.load.return_value = None
    mock_provider_class.return_value = mock_provider

    # Should raise S3AssumeRoleException
    with pytest.raises(S3AssumeRoleException) as exc_info:
        cached_load_s3filestore_credentials()

    assert 'Failed to load credentials from EC2 instance metadata' in str(exc_info.value)


@mock.patch('ckanext.s3filestore.caching.role_name_or_arn', 'arn:aws:iam::123456789012:role/TestRole')
@mock.patch('ckanext.s3filestore.caching.region', 'us-east-1')
@mock.patch('ckanext.s3filestore.caching.session_name', 'test-session')
@mock.patch('ckanext.s3filestore.caching.InstanceMetadataProvider')
@mock.patch('ckanext.s3filestore.caching.InstanceMetadataFetcher')
@mock.patch('ckanext.s3filestore.caching.boto3.Session')
def test_assume_role_failure(mock_session_class, mock_fetcher_class, mock_provider_class):
    """Test error handling when AssumeRole fails."""
    # Mock instance metadata credentials
    mock_creds = mock.Mock()
    mock_creds.access_key = 'MOCK_ACCESS_KEY'
    mock_creds.secret_key = 'MOCK_SECRET_KEY'
    mock_creds.token = 'MOCK_TOKEN'

    mock_provider = mock.Mock()
    mock_provider.load.return_value = mock_creds
    mock_provider_class.return_value = mock_provider

    # Mock STS client to raise exception
    mock_sts = mock.Mock()
    mock_sts.assume_role.side_effect = Exception('Access denied')

    mock_session = mock.Mock()
    mock_session.client.return_value = mock_sts
    mock_session_class.return_value = mock_session

    # Should raise S3AssumeRoleException
    with pytest.raises(S3AssumeRoleException) as exc_info:
        cached_load_s3filestore_credentials()

    assert 'Unexpected error' in str(exc_info.value)


@mock.patch('ckanext.s3filestore.caching.role_name_or_arn', 'arn:aws:iam::123456789012:role/TestRole')
@mock.patch('ckanext.s3filestore.caching.region', 'us-east-1')
@mock.patch('ckanext.s3filestore.caching.session_name', 'test-session')
@mock.patch('ckanext.s3filestore.caching.InstanceMetadataProvider')
@mock.patch('ckanext.s3filestore.caching.InstanceMetadataFetcher')
@mock.patch('ckanext.s3filestore.caching.boto3.Session')
def test_timezone_aware_expiration(mock_session_class, mock_fetcher_class, mock_provider_class):
    """Test that expiration time is converted to timezone-aware datetime."""
    # Mock instance metadata credentials
    mock_creds = mock.Mock()
    mock_creds.access_key = 'MOCK_ACCESS_KEY'
    mock_creds.secret_key = 'MOCK_SECRET_KEY'
    mock_creds.token = 'MOCK_TOKEN'

    mock_provider = mock.Mock()
    mock_provider.load.return_value = mock_creds
    mock_provider_class.return_value = mock_provider

    # Mock STS client with timezone-naive datetime
    expiration_time = datetime.now()  # Intentionally naive
    mock_sts = mock.Mock()
    mock_sts.assume_role.return_value = {
        'Credentials': {
            'AccessKeyId': 'ASSUMED_KEY',
            'SecretAccessKey': 'ASSUMED_SECRET',
            'SessionToken': 'ASSUMED_TOKEN',
            'Expiration': expiration_time
        }
    }

    mock_session = mock.Mock()
    mock_session.client.return_value = mock_sts
    mock_session_class.return_value = mock_session

    # Call function
    credentials = cached_load_s3filestore_credentials()

    # Verify expiration is timezone-aware
    assert credentials['Expiration'].tzinfo is not None
    assert credentials['Expiration'].tzinfo == timezone.utc


@mock.patch('ckanext.s3filestore.caching.role_name_or_arn', 'arn:aws:iam::123456789012:role/TestRole')
@mock.patch('ckanext.s3filestore.caching.region', 'us-east-1')
@mock.patch('ckanext.s3filestore.caching.session_name', 'test-session')
@mock.patch('ckanext.s3filestore.caching.InstanceMetadataProvider')
@mock.patch('ckanext.s3filestore.caching.InstanceMetadataFetcher')
@mock.patch('ckanext.s3filestore.caching.boto3.Session')
def test_caching_behavior(mock_session_class, mock_fetcher_class, mock_provider_class):
    """Test that dogpile caching works - second call doesn't hit AWS."""
    # Mock instance metadata credentials
    mock_creds = mock.Mock()
    mock_creds.access_key = 'MOCK_ACCESS_KEY'
    mock_creds.secret_key = 'MOCK_SECRET_KEY'
    mock_creds.token = 'MOCK_TOKEN'

    mock_provider = mock.Mock()
    mock_provider.load.return_value = mock_creds
    mock_provider_class.return_value = mock_provider

    # Mock STS client
    expiration_time = datetime.now(timezone.utc) + timedelta(hours=1)
    mock_sts = mock.Mock()
    mock_sts.assume_role.return_value = {
        'Credentials': {
            'AccessKeyId': 'ASSUMED_KEY',
            'SecretAccessKey': 'ASSUMED_SECRET',
            'SessionToken': 'ASSUMED_TOKEN',
            'Expiration': expiration_time
        }
    }

    mock_session = mock.Mock()
    mock_session.client.return_value = mock_sts
    mock_session_class.return_value = mock_session

    # First call - should hit AWS
    credentials1 = cached_load_s3filestore_credentials()

    # Second call - should use cache
    credentials2 = cached_load_s3filestore_credentials()

    # Verify same credentials returned
    assert credentials1 == credentials2

    # Verify assume_role was only called once (cached on second call)
    assert mock_sts.assume_role.call_count == 1


@mock.patch('ckanext.s3filestore.caching.role_name_or_arn', 'arn:aws:iam::123456789012:role/TestRole')
@mock.patch('ckanext.s3filestore.caching.region', 'us-east-1')
@mock.patch('ckanext.s3filestore.caching.session_name', 'test-session')
@mock.patch('ckanext.s3filestore.caching.InstanceMetadataProvider')
@mock.patch('ckanext.s3filestore.caching.InstanceMetadataFetcher')
@mock.patch('ckanext.s3filestore.caching.boto3.Session')
def test_get_fresh_s3_credentials_auto_refresh_on_expiry(mock_session_class, mock_fetcher_class, mock_provider_class):
    """Test that get_fresh_s3_credentials() auto-refreshes when credentials expire soon."""
    # Mock instance metadata credentials
    mock_creds = mock.Mock()
    mock_creds.access_key = 'MOCK_ACCESS_KEY'
    mock_creds.secret_key = 'MOCK_SECRET_KEY'
    mock_creds.token = 'MOCK_TOKEN'

    mock_provider = mock.Mock()
    mock_provider.load.return_value = mock_creds
    mock_provider_class.return_value = mock_provider

    # Mock STS client - first call returns credentials expiring in 3 minutes
    expiration_time_old = datetime.now(timezone.utc) + timedelta(minutes=3)
    expiration_time_new = datetime.now(timezone.utc) + timedelta(hours=1)

    call_count = [0]
    def mock_assume_role(**kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            # First call - credentials expiring in 3 minutes
            return {
                'Credentials': {
                    'AccessKeyId': 'OLD_KEY',
                    'SecretAccessKey': 'OLD_SECRET',
                    'SessionToken': 'OLD_TOKEN',
                    'Expiration': expiration_time_old
                }
            }
        else:
            # Second call - fresh credentials expiring in 60 minutes
            return {
                'Credentials': {
                    'AccessKeyId': 'NEW_KEY',
                    'SecretAccessKey': 'NEW_SECRET',
                    'SessionToken': 'NEW_TOKEN',
                    'Expiration': expiration_time_new
                }
            }

    mock_sts = mock.Mock()
    mock_sts.assume_role = mock_assume_role

    mock_session = mock.Mock()
    mock_session.client.return_value = mock_sts
    mock_session_class.return_value = mock_session

    # First call - should get credentials expiring in 3 minutes
    credentials = get_fresh_s3_credentials()

    # Should have invalidated cache and refreshed (expiring in <5 min)
    assert credentials['AccessKeyId'] == 'NEW_KEY'
    assert mock_sts.assume_role.call_count == 2  # Called twice (initial + refresh)
