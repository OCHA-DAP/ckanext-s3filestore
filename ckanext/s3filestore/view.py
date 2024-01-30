import os
import logging
import mimetypes
import hashlib


from flask import Blueprint, make_response, send_file
from botocore.exceptions import ClientError

import ckan.model as model
import ckan.lib.uploader as uploader

import ckan.plugins.toolkit as tk

from ckanext.s3filestore.uploader import S3Uploader
from ckanext.s3filestore.helpers import generate_temporary_link, CachedDownloadStorageHelper

log = logging.getLogger(__name__)

NotFound = tk.ObjectNotFound
NotAuthorized = tk.NotAuthorized
get_action = tk.get_action
config = tk.config
abort = tk.abort
request = tk.request
redirect = tk.redirect_to
_ = tk._
g = tk.g

s3filestore = Blueprint(u's3filestore', __name__)

datasets_for_download_with_cache = None


def download(id, resource_id, filename=None):
    '''
    Provide a download by either redirecting the user to the url stored or
    downloading the uploaded file from S3.
    '''
    context = {'model': model, 'session': model.Session,
               'user': g.user or g.author, 'auth_user_obj': g.userobj}

    try:
        rsc = get_action('resource_show')(context, {'id': resource_id})
        dataset_dict = get_action('package_show')(context, {'id': id})
    except NotFound:
        return abort(404, _('Resource not found'))
    except NotAuthorized:
        return abort(401, _('Unauthorized to read resource %s') % id)

    if rsc.get('url_type') == 'upload':
        upload = uploader.get_resource_uploader(rsc)
        bucket_name = config.get('ckanext.s3filestore.aws_bucket_name')
        region = config.get('ckanext.s3filestore.region_name')
        host_name = config.get('ckanext.s3filestore.host_name')
        bucket = upload.get_s3_bucket(bucket_name)

        if filename is None:
            filename = os.path.basename(rsc['url'])
        key_path = upload.get_path(rsc['id'], filename)
        key = filename

        if key is None:
            log.warn('Key \'{0}\' not found in bucket \'{1}\''
                     .format(key_path, bucket_name))

        try:
            # Small workaround to manage downloading of large files
            # We are using redirect to minio's resource public URL
            s3 = upload.get_s3_session()
            client = s3.client(service_name='s3', endpoint_url=host_name)
            # url = client.generate_presigned_url(ClientMethod='get_object',
            #                                     Params={'Bucket': bucket.name,
            #                                             'Key': key_path},
            #                                     ExpiresIn=60)
            url = generate_temporary_link(client, bucket.name, key_path)
            if _should_use_download_with_cache(dataset_dict['name']):
                return _resource_download_with_cache(url, filename, rsc)
            else:
                return redirect(url)

        except ClientError as ex:
            if ex.response['Error']['Code'] == 'NoSuchKey':
                # attempt fallback
                if config.get(
                    'ckanext.s3filestore.filesystem_download_fallback',
                    False):
                    log.info('Attempting filesystem fallback for resource {0}'
                             .format(resource_id))
                    url = tk.url_for(
                        controller='ckanext.s3filestore.controller:S3Controller',
                        action='filesystem_resource_download',
                        id=id,
                        resource_id=resource_id,
                        filename=filename)
                    return redirect(url)

                return abort(404, _('Resource data not found'))
            else:
                raise ex
    elif u'url' not in rsc:
        return abort(404, _(u'No download is available'))
    return redirect(rsc[u'url'])


def filesystem_resource_download(id, resource_id, filename=None):
    """
    A fallback controller action to download resources from the
    filesystem. A copy of the action from
    `ckan.controllers.package:PackageController.resource_download`.

    Provide a direct download by either redirecting the user to the url
    stored or downloading an uploaded file directly.
    """
    context = {'model': model, 'session': model.Session,
               'user': g.user or g.author, 'auth_user_obj': g.userobj}

    try:
        rsc = get_action('resource_show')(context, {'id': resource_id})
        get_action('package_show')(context, {'id': id})
    except NotFound:
        return abort(404, _('Resource not found'))
    except NotAuthorized:
        return abort(401, _('Unauthorized to read resource %s') % id)

    if rsc.get('url_type') == 'upload':
        upload = uploader.ResourceUpload(rsc)
        filepath = upload.get_path(rsc['id'])
        # fileapp = paste.fileapp.FileApp(filepath)
        try:
            response = send_file(filepath)
            # status, headers, app_iter = request.call_application(fileapp)
        except OSError:
            return abort(404, _('Resource data not found'))
        # response.headers.update(dict(headers))
        content_type, content_enc = mimetypes.guess_type(rsc.get('url', ''))
        if content_type:
            response.headers['Content-Type'] = content_type
        # response.status = status
        return response
    elif 'url' not in rsc:
        return abort(404, _('No download is available'))
    return redirect(str(rsc['url']))


def uploaded_file_redirect(upload_to, filename):
    '''Redirect static file requests to their location on S3.'''
    host_name = config.get('ckanext.s3filestore.host_name')
    # Remove last characted if it's a slash
    if host_name[-1] == '/':
        host_name = host_name[:-1]
    storage_path = S3Uploader.get_storage_path(upload_to)
    filepath = os.path.join(storage_path, filename)
    # host = config.get('ckanext.s3.filestore.hostname')
    # redirect_url = 'https://{bucket_name}.minio.omc.ckan.io/{filepath}' \
    #     .format(bucket_name=config.get('ckanext.s3filestore.aws_bucket_name'),
    #             filepath=filepath)
    redirect_url = '{host_name}/{bucket_name}/{filepath}' \
        .format(bucket_name=config.get('ckanext.s3filestore.aws_bucket_name'),
                filepath=filepath,
                host_name=host_name)
    return redirect(redirect_url)


def _should_use_download_with_cache(dataset_name):
    global datasets_for_download_with_cache
    if not datasets_for_download_with_cache:
        datasets_str = config.get('hdx.download_with_cache.datasets')
        if datasets_str:
            datasets_for_download_with_cache = set(datasets_str.split(','))
    if datasets_for_download_with_cache \
        and dataset_name in datasets_for_download_with_cache:
        return True
    return False


def _compute_cached_filename(original_filename, resource_dict):
    id = resource_dict['id']
    last_modified = resource_dict.get('last_modified', '')
    key = (id + last_modified).encode('utf-8')
    name = hashlib.sha1(key).hexdigest()
    parts = original_filename.split('.')[:]
    parts[0] = name
    filename = '.'.join(parts)
    return filename


def _get_cached_download_storage_helper(filename, url):
    return CachedDownloadStorageHelper(filename, url)


def _resource_download_with_cache(url, original_filename, resource_dict):
    filename = _compute_cached_filename(original_filename, resource_dict)

    storage_helper = _get_cached_download_storage_helper(filename, url)
    storage_helper.create_folder_if_needed()
    storage_helper.download_file_if_needed()

    return _prepare_cached_response(storage_helper.full_file_path)


def _prepare_cached_response(full_file_path):
    try:
        response = send_file(full_file_path)

        # fileapp = paste.fileapp.FileApp(full_file_path)
        # status, headers, app_iter = request.call_application(fileapp)
        # response.headers.update(dict(headers))
        content_type, content_enc = mimetypes.guess_type(full_file_path)
        if content_type:
            response.headers['Content-Type'] = content_type
        return response

    except OSError:
        return abort(404, _('Resource data not found'))


s3filestore.add_url_rule(u'/dataset/<id>/resource/<resource_id>/download', view_func=download)
s3filestore.add_url_rule(u'/dataset/<id>/resource/<resource_id>/download/<filename>', view_func=download)
s3filestore.add_url_rule(u'/uploads/<upload_to>/<filename>', view_func=uploaded_file_redirect)
