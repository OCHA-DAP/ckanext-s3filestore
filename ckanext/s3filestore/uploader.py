import os
import cgi
import logging
import datetime
import mimetypes

import boto3
import botocore

import ckantoolkit as toolkit

import ckan.model as model
import ckan.lib.munge as munge

from six import text_type

from ckanext.s3filestore.caching import get_fresh_s3_credentials


if toolkit.check_ckan_version(min_version='2.7.0'):
    from werkzeug.datastructures import FileStorage as FlaskFileStorage
    ALLOWED_UPLOAD_TYPES = (cgi.FieldStorage, FlaskFileStorage)
else:
    ALLOWED_UPLOAD_TYPES = (cgi.FieldStorage)

config = toolkit.config
log = logging.getLogger(__name__)

_storage_path = None
_max_resource_size = None
_max_image_size = None


def _get_underlying_file(wrapper):
    if isinstance(wrapper, FlaskFileStorage):
        return wrapper.stream
    return wrapper.file


class S3FileStoreException(Exception):
    pass


class BaseS3Uploader(object):

    def __init__(self):
        self.bucket_name = config.get('ckanext.s3filestore.aws_bucket_name')
        self.p_key = config.get('ckanext.s3filestore.aws_access_key_id')
        self.s_key = config.get('ckanext.s3filestore.aws_secret_access_key')
        self.region = config.get('ckanext.s3filestore.region_name')
        self.signature = config.get('ckanext.s3filestore.signature_version')
        self.host_name = config.get('ckanext.s3filestore.host_name')
        # Assume role configuration
        self.use_assume_role = toolkit.asbool(config.get('ckanext.s3filestore.aws_use_assume_role', False))
        self.role_arn = config.get('ckanext.s3filestore.aws_role_arn')
        self.role_session_name = config.get('ckanext.s3filestore.aws_role_session_name', 'ckan-s3filestore-session')

        # If using AssumeRole, remove AWS credentials from environment to force boto3
        # to use instance profile credentials
        if self.use_assume_role and self.role_arn:
            if 'AWS_ACCESS_KEY_ID' in os.environ:
                del os.environ['AWS_ACCESS_KEY_ID']
                log.info('Removed AWS_ACCESS_KEY_ID from environment for AssumeRole')
            if 'AWS_SECRET_ACCESS_KEY' in os.environ:
                del os.environ['AWS_SECRET_ACCESS_KEY']
                log.info('Removed AWS_SECRET_ACCESS_KEY from environment for AssumeRole')

        # Note: We don't cache self.bucket here to avoid credential expiration issues
        # with AssumeRole temporary credentials. Each operation (upload_to_key, clear_key)
        # creates a fresh S3 session via get_s3_session(), ensuring credentials are always valid.
        # Bucket validation at startup is handled by plugin.py configure() method.

    def get_directory(self, id, storage_path):
        directory = os.path.join(storage_path, id)
        return directory

    def get_s3_session(self):
        """
        Create and return a boto3 session.

        Two modes of operation:
        1. AssumeRole mode (when use_assume_role is True and role_arn is provided):
           - Uses cached_load_s3filestore_credentials() for Redis-cached credentials
           - Lazy refresh: dogpile automatically reuses valid credentials from Redis
           - Multi-process safe: all nginx unit processes share the same Redis cache
           - No locks needed: dogpile handles concurrent access with distributed locks
        2. Standard mode (default):
           - Uses explicit AWS access key and secret key from config
        """
        if self.use_assume_role and self.role_arn:
            log.info('S3 Authentication: Using AssumeRole mode with Redis-cached credentials')

            # Load credentials from cache (Redis) or create new ones if expired
            # get_fresh_s3_credentials() validates expiration and auto-refreshes if needed
            log.info('Getting S3 credentials...')
            try:
                credentials = get_fresh_s3_credentials()
                # Mask AccessKeyId - show only first 2 and last 2 chars
                access_key = credentials.get('AccessKeyId', 'None')
                if access_key != 'None' and len(access_key) > 4:
                    masked_key = '{0}..{1}'.format(access_key[:2], access_key[-2:])
                else:
                    masked_key = access_key
                log.info('Received credentials - AccessKeyId: {0}, Expiration: {1}'.format(
                    masked_key,
                    credentials.get('Expiration', 'None')
                ))
            except Exception as e:
                log.error('Failed to load credentials: {0}'.format(str(e)), exc_info=True)
                raise

            # Create session with cached credentials
            return boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=self.region
            )
        else:
            # Use standard credentials with explicit keys
            log.info('S3 Authentication: Using explicit credentials mode (access key)')
            return boto3.Session(
                aws_access_key_id=self.p_key,
                aws_secret_access_key=self.s_key,
                region_name=self.region
            )

    def get_s3_bucket(self, bucket_name):
        '''Return a boto bucket, creating it if it doesn't exist.'''

        # make s3 connection using boto3

        s3 = self.get_s3_session().resource('s3', endpoint_url=self.host_name,
                                            config=botocore.client.Config(
                                             signature_version=self.signature))
        try:
            s3.meta.client.head_bucket(Bucket=bucket_name)
            bucket = s3.Bucket(bucket_name)
        except botocore.exceptions.ClientError as e:
            error_code = int(e.response['Error']['Code'])
            if error_code == 404:
                log.warning('Bucket {0} could not be found, ' +
                            'attempting to create it...'.format(bucket_name))
                try:
                    bucket = s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={
                        'LocationConstraint': self.region})
                    log.info(
                        'Bucket {0} succesfully created'.format(bucket_name))
                except botocore.exceptions.ClientError as e:
                    log.warning('Could not create bucket {0}: {1}'.format(
                        bucket_name, str(e)))
            elif error_code == 403:
                raise S3FileStoreException(
                    'Access to bucket {0} denied'.format(bucket_name))
            else:
                raise S3FileStoreException(
                    'Something went wrong for bucket {0}'.format(bucket_name))

        return bucket

    def upload_to_key(self, filepath, upload_file, make_public=False, metadata=None):
        '''Uploads the `upload_file` to `filepath` on `self.bucket`.'''
        metadata = {} if metadata is None else metadata
        upload_file.seek(0)

        session = self.get_s3_session()
        s3 = session.resource('s3', endpoint_url=self.host_name,
                              config=botocore.client.Config(signature_version=self.signature))
        try:
            s3.Object(self.bucket_name, filepath).put(
                Body=upload_file.read(),
                ContentType=getattr(self, 'mimetype', 'application/octet-stream') or 'application/octet-stream',
                Metadata=metadata)
            log.info("Succesfully uploaded {0} to S3!".format(filepath))
        except Exception as e:
            log.error('Something went very very wrong for {0}'.format(str(e)))
            raise e

    def clear_key(self, filepath):
        '''Deletes the contents of the key at `filepath` on `self.bucket`.'''
        session = self.get_s3_session()
        s3 = session.resource('s3', endpoint_url=self.host_name, config=botocore.client.Config(
                             signature_version=self.signature))
        try:
            s3.Object(self.bucket_name, filepath).delete()
        except Exception as e:
            raise e


class S3Uploader(BaseS3Uploader):

    '''
    An uploader class to replace local file storage with Amazon Web Services
    S3 for general files (e.g. Group cover images).
    '''

    def __init__(self, upload_to, old_filename=None):
        '''Setup the uploader. Additional setup is performed by
        update_data_dict(), and actual uploading performed by `upload()`.

        Create a storage path in the format:
        <ckanext.s3filestore.aws_storage_path>/storage/uploads/<upload_to>/
        '''

        super(S3Uploader, self).__init__()

        self.storage_path = self.get_storage_path(upload_to)

        self.filename = None
        self.filepath = None

        self.old_filename = old_filename
        if old_filename:
            self.old_filepath = os.path.join(self.storage_path, old_filename)

    @classmethod
    def get_storage_path(cls, upload_to):
        path = config.get('ckanext.s3filestore.aws_storage_path', '')
        return os.path.join(path, 'storage', 'uploads', upload_to)

    def update_data_dict(self, data_dict, url_field, file_field, clear_field):
        '''Manipulate data from the data_dict. This needs to be called before it
        reaches any validators.

        `url_field` is the name of the field where the upload is going to be.

        `file_field` is name of the key where the FieldStorage is kept (i.e
        the field where the file data actually is).

        `clear_field` is the name of a boolean field which requests the upload
        to be deleted.
        '''

        self.url = data_dict.get(url_field, '')
        self.clear = data_dict.pop(clear_field, None)
        self.file_field = file_field
        self.upload_field_storage = data_dict.pop(file_field, None)

        if not self.storage_path:
            return
        if isinstance(self.upload_field_storage, ALLOWED_UPLOAD_TYPES) and self.upload_field_storage.filename:
            self.filename = self.upload_field_storage.filename
            self.filename = str(datetime.datetime.utcnow()) + self.filename
            self.filename = munge.munge_filename_legacy(self.filename)
            self.filepath = os.path.join(self.storage_path, self.filename)
            data_dict[url_field] = self.filename
            self.upload_file = _get_underlying_file(self.upload_field_storage)
        # keep the file if there has been no change
        elif self.old_filename and not self.old_filename.startswith('http'):
            if not self.clear:
                data_dict[url_field] = self.old_filename
            if self.clear and self.url == self.old_filename:
                data_dict[url_field] = ''

    def upload(self, max_size=2):
        '''Actually upload the file.

        This should happen just before a commit but after the data has been
        validated and flushed to the db. This is so we do not store anything
        unless the request is actually good. max_size is size in MB maximum of
        the file'''

        # If a filename has been provided (a file is being uploaded) write the
        # file to the appropriate key in the AWS bucket.
        if self.filename:
            self.upload_to_key(self.filepath, self.upload_file,
                               make_public=True)
            self.clear = True

        if (self.clear and self.old_filename
                and not self.old_filename.startswith('http')):
            self.clear_key(self.old_filepath)


class S3ResourceUploader(BaseS3Uploader):

    '''
    An uploader class to replace local file storage with Amazon Web Services
    S3 for resource files.
    '''

    def __init__(self, resource):
        '''Setup the resource uploader. Actual uploading performed by
        `upload()`.

        Create a storage path in the format:
        <ckanext.s3filestore.aws_storage_path>/resources/
        '''

        super(S3ResourceUploader, self).__init__()

        path = config.get('ckanext.s3filestore.aws_storage_path', '')
        self.storage_path = os.path.join(path, 'resources')
        self.filename = None
        self.old_filename = None

        upload_field_storage = resource.pop('upload', None)
        self.clear = resource.pop('clear_upload', None)

        self.qa_autoscan = None

        if isinstance(upload_field_storage, ALLOWED_UPLOAD_TYPES):
            self.filename = upload_field_storage.filename
            self.filename = munge.munge_filename(self.filename)
            self.qa_autoscan = self._should_be_autoscanned(resource)
            resource['url'] = self.filename
            resource['url_type'] = 'upload'
            resource['last_modified'] = datetime.datetime.utcnow()
            self.mimetype = resource.get('mimetype') if not self.filename.lower().endswith('csv') else 'text/csv'
            if not self.mimetype:
                try:
                    self.mimetype = resource['mimetype'] = mimetypes.guess_type(self.filename, strict=False)[0]
                except Exception:
                    pass
            self.upload_file = _get_underlying_file(upload_field_storage)
        elif self.clear and resource.get('id'):
            # New, not yet created resources can be marked for deletion if the
            # users cancels an upload and enters a URL instead.
            old_resource = model.Session.query(model.Resource) \
                .get(resource['id'])
            self.old_filename = old_resource.url
            resource['url_type'] = ''

    def get_path(self, id, filename):
        '''Return the key used for this resource in S3.

        Keys are in the form:
        <ckanext.s3filestore.aws_storage_path>/resources/<resource id>/<filename>

        e.g.:
        my_storage_path/resources/165900ba-3c60-43c5-9e9c-9f8acd0aa93f/data.csv
        '''
        directory = self.get_directory(id, self.storage_path)
        filepath = os.path.join(directory, filename)
        return filepath

    def upload(self, id, max_size=10):
        '''Upload the file to S3.'''

        # If a filename has been provided (a file is being uploaded) write the
        # file to the appropriate key in the AWS bucket.
        if self.filename:
            filepath = self.get_path(id, self.filename)
            metadata = {}
            if self.qa_autoscan:
                metadata['autoscan'] = 'true'
            self.upload_to_key(filepath, self.upload_file, metadata=metadata)

        # The resource form only sets self.clear (via the input clear_upload)
        # to True when an uploaded file is not replaced by another uploaded
        # file, only if it is replaced by a link. If the uploaded file is
        # replaced by a link, we should remove the previously uploaded file to
        # clean up the file system.
        if self.clear and self.old_filename:
            filepath = self.get_path(id, self.old_filename)
            self.clear_key(filepath)

    def _should_be_autoscanned(self, resource):
        is_spreadsheet = False
        is_human = False
        parts = self.filename.lower().split('.')
        if len(parts) > 0 and parts[-1] in ['csv', 'xls', 'xlsx']:
            is_spreadsheet = True

        try:
            request = toolkit.request
            browser = request.user_agent.browser
            platform = request.user_agent.platform
            if not browser and not platform:
                # only when running pytests
                import ua_parser.user_agent_parser as useragent
                parsed_ua = useragent.Parse(request.user_agent.string)
                browser = parsed_ua.get('user_agent', {}).get('family', '')
                browser = browser if browser != 'Other' else None
                platform = parsed_ua.get('os', {}).get('family', '')
                platform = platform if platform != 'Other' else None
            if browser and platform:
                is_human = True

        except (TypeError, RuntimeError) as e:
            log.warning('An exception was thrown while trying to read request data. '
                        'This is normal when running tests: ' + text_type(e) )

        return is_human and is_spreadsheet




    @property
    def filesize(self):
        if hasattr(self, 'upload_file'):
            try:
                self.upload_file.seek(0,2)
                size = self.upload_file.tell()
                return size
            except Exception as ex:
                log.error(ex)
        return 0
