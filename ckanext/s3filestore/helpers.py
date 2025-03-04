import os
import os.path
import requests

from ckantoolkit import config


def generate_temporary_link(client, bucket_name, key_path, force_download=False, expires_in=None, http_method=None):

    if not expires_in:
        expires_in = config.get('ckanext.s3filestore.link_expires_in_seconds', 60)

    params = {
        'Bucket': bucket_name,
        'Key': key_path,
    }

    if force_download:
        filename = key_path.split('/')[-1]
        params['ResponseContentDisposition'] = f'attachment; filename="{filename}"'

    # Use the passed HTTP method or default to GET
    kwargs = {}
    if http_method:
        kwargs['HttpMethod'] = http_method

    url = client.generate_presigned_url(
        ClientMethod='get_object',
        Params=params,
        ExpiresIn=expires_in,
        **kwargs
    )

    return url


class CachedDownloadStorageHelper(object):
    def __init__(self, filename, url):
        self.folder = config.get('hdx.download_with_cache.folder', '/tmp/')
        if not self.folder.endswith('/'):
            self.folder += '/'

        self.filename = filename
        self.full_file_path = self.folder + self.filename
        self.url = url

    def _folder_exists(self):
        return os.path.exists(self.folder)

    def _file_exists(self):
        return os.path.exists(self.full_file_path)

    def _create_folder(self):
        os.makedirs(self.folder)

    def _download_file(self):
        r = requests.get(self.url)
        with open(self.full_file_path, 'wb') as f:
            f.write(r.content)

    def create_folder_if_needed(self):
        if not self._folder_exists():
            self._create_folder()

    def download_file_if_needed(self):
        if not self._file_exists():
            self._download_file()
