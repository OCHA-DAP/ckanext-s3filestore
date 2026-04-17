# -*- coding: utf-8 -*-
"""
Unit tests for get_cached_s3_credentials().

The full AssumeRole logic and dogpile caching behaviour are tested in
ckanext-hdx_theme's test_aws_credentials.py.
Here we test only what is specific to this module:
  1. Config validation (missing role_arn / region raises before hitting AWS)
  2. That get_cached_aws_credentials is called with the correct S3 config values
"""
from unittest import mock

import pytest

from ckanext.hdx_theme.helpers.aws_credentials import AwsAssumeRoleException
from ckanext.s3filestore.caching import get_cached_s3_credentials

_FAKE_CREDS = {
    'access_key': 'KEY', 'secret_key': 'SECRET', 'session_token': 'TOKEN',
    'expiration': None, 'region': 'us-east-1',
}


@mock.patch('ckanext.s3filestore.caching.role_name_or_arn', 'arn:aws:iam::123456789012:role/S3Role')
@mock.patch('ckanext.s3filestore.caching.region', 'us-east-1')
@mock.patch('ckanext.s3filestore.caching.session_name', 'ckan-s3filestore-session')
@mock.patch('ckanext.s3filestore.caching.get_cached_aws_credentials')
def test_delegates_to_shared_cache_with_s3_config(mock_cached):
    """get_cached_s3_credentials passes its S3 config to get_cached_aws_credentials."""
    mock_cached.return_value = _FAKE_CREDS

    result = get_cached_s3_credentials()

    mock_cached.assert_called_once_with(
        'arn:aws:iam::123456789012:role/S3Role',
        'us-east-1',
        'ckan-s3filestore-session',
    )
    assert result == _FAKE_CREDS


@mock.patch('ckanext.s3filestore.caching.role_name_or_arn', None)
@mock.patch('ckanext.s3filestore.caching.region', 'us-east-1')
def test_missing_role_arn_raises_before_aws_call():
    with pytest.raises(AwsAssumeRoleException, match='aws_role_arn'):
        get_cached_s3_credentials()


@mock.patch('ckanext.s3filestore.caching.role_name_or_arn', 'arn:aws:iam::123456789012:role/S3Role')
@mock.patch('ckanext.s3filestore.caching.region', None)
def test_missing_region_raises_before_aws_call():
    with pytest.raises(AwsAssumeRoleException, match='region_name'):
        get_cached_s3_credentials()
