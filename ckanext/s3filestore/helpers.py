from ckantoolkit import config


def generate_temporary_link(client, bucket_name, key_path, expires_in=None):

    if not expires_in:
        expires_in = config.get('ckanext.s3filestore.link_expires_in_seconds', 60)
    url = client.generate_presigned_url(ClientMethod='get_object',
                                        Params={'Bucket': bucket_name,
                                                'Key': key_path},
                                        ExpiresIn=expires_in)

    return url
