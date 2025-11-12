# from routes.mapper import SubMapper
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

import ckanext.s3filestore.uploader
from ckanext.s3filestore.view import s3filestore


class S3FileStorePlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.IUploader)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IConfigDeclaration)
    # plugins.implements(plugins.IRoutes, inherit=True)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')

    # IConfigDeclaration

    def declare_config_options(self, declaration, key):
        # Only declare the new AssumeRole configuration options
        # Other options are already declared by CKAN's blanket plugin
        # declaration.declare(key.ckanext.s3filestore.aws_bucket_name)
        # declaration.declare(key.ckanext.s3filestore.aws_access_key_id)
        # declaration.declare(key.ckanext.s3filestore.aws_secret_access_key)
        # declaration.declare(key.ckanext.s3filestore.region_name)
        # declaration.declare(key.ckanext.s3filestore.signature_version)
        # declaration.declare(key.ckanext.s3filestore.host_name)
        # declaration.declare(key.ckanext.s3filestore.aws_storage_path)
        # declaration.declare(key.ckanext.s3filestore.check_access_on_startup)
        # declaration.declare(key.ckanext.s3filestore.filesystem_download_fallback)
        # declaration.declare(key.ckanext.s3filestore.link_expires_in_seconds)
        # AssumeRole configuration
        declaration.declare(key.ckanext.s3filestore.aws_use_assume_role, False)
        declaration.declare(key.ckanext.s3filestore.aws_role_arn)
        declaration.declare(key.ckanext.s3filestore.aws_role_session_name, 'ckan-s3filestore-session')

    # IConfigurable

    def configure(self, config):
        # Certain config options must exists for the plugin to work. Raise an
        # exception if they're missing.
        missing_config = "{0} is not configured. Please amend your .ini file."

        # Check if using AssumeRole mode
        use_assume_role = toolkit.asbool(config.get('ckanext.s3filestore.aws_use_assume_role', False))

        # Always required options
        required_options = (
            'ckanext.s3filestore.aws_bucket_name',
            'ckanext.s3filestore.region_name',
            'ckanext.s3filestore.signature_version',
            'ckanext.s3filestore.host_name'
        )

        # If NOT using AssumeRole, also require access keys
        if not use_assume_role:
            required_options += (
                'ckanext.s3filestore.aws_access_key_id',
                'ckanext.s3filestore.aws_secret_access_key',
            )
        else:
            # If using AssumeRole, require role ARN
            if not config.get('ckanext.s3filestore.aws_role_arn'):
                raise RuntimeError('ckanext.s3filestore.aws_role_arn is required when aws_use_assume_role is true')

        for option in required_options:
            if not config.get(option, None):
                raise RuntimeError(missing_config.format(option))

        # Check that options actually work, if not exceptions will be raised
        if toolkit.asbool(
                config.get('ckanext.s3filestore.check_access_on_startup',
                           True)):
            ckanext.s3filestore.uploader.BaseS3Uploader().get_s3_bucket(
                config.get('ckanext.s3filestore.aws_bucket_name'))

    # IUploader

    def get_resource_uploader(self, data_dict):
        '''Return an uploader object used to upload resource files.'''
        return ckanext.s3filestore.uploader.S3ResourceUploader(data_dict)

    def get_uploader(self, upload_to, old_filename=None):
        '''Return an uploader object used to upload general files.'''
        return ckanext.s3filestore.uploader.S3Uploader(upload_to,
                                                       old_filename)

    # IRoutes

    # def before_map(self, map):
    #     with SubMapper(map, controller='ckanext.s3filestore.controller:S3Controller') as m:
            # Override the resource download links
            # m.connect('resource_download',
            #           '/dataset/{id}/resource/{resource_id}/download',
            #           action='resource_download')
            # m.connect('resource_download',
            #           '/dataset/{id}/resource/{resource_id}/download/{filename}',
            #           action='resource_download')

            # fallback controller action to download from the filesystem
            # m.connect('filesystem_resource_download',
            #           '/dataset/{id}/resource/{resource_id}/fs_download/{filename}',
            #           action='filesystem_resource_download')

            # Intercept the uploaded file links (e.g. group images)
            # m.connect('uploaded_file', '/uploads/{upload_to}/{filename}',
            #           action='uploaded_file_redirect')

        # return map

    # IBlueprint
    def get_blueprint(self):
        return s3filestore
