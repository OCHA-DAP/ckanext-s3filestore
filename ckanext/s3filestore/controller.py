import mimetypes
import paste.fileapp
import pylons.config as config

import ckan.logic as logic
import ckan.lib.base as base
import ckan.model as model
import ckan.lib.uploader as uploader

from ckan.common import _, request, c, response

import logging
log = logging.getLogger(__name__)

NotFound = logic.NotFound
NotAuthorized = logic.NotAuthorized
get_action = logic.get_action
abort = base.abort
redirect = base.redirect


class S3Controller(base.BaseController):

    def resource_download(self, id, resource_id, filename=None):
        """
        Provide a download by either redirecting the user to the url stored or
        downloading the uploaded file from S3.
        """
        context = {'model': model, 'session': model.Session,
                   'user': c.user or c.author, 'auth_user_obj': c.userobj}

        try:
            rsc = get_action('resource_show')(context, {'id': resource_id})
            get_action('package_show')(context, {'id': id})
        except NotFound:
            abort(404, _('Resource not found'))
        except NotAuthorized:
            abort(401, _('Unauthorized to read resource %s') % id)

        if rsc.get('url_type') == 'upload':
            upload = uploader.get_uploader(rsc)
            bucket_name = config.get('ckanext.s3filestore.aws_bucket_name')
            bucket = upload.get_s3_bucket(bucket_name)

            key_path = upload.get_path(rsc['id'])

            try:
                key = bucket.get_key(key_path)
            except Exception as e:
                raise e

            if key is None:
                abort(404, _('Resource data not found'))
            contents = key.get_contents_as_string()
            key.close()

            dataapp = paste.fileapp.DataApp(contents)

            try:
                status, headers, app_iter = request.call_application(dataapp)
            except OSError:
                abort(404, _('Resource data not found'))

            response.headers.update(dict(headers))
            response.status = status
            content_type, x = mimetypes.guess_type(rsc.get('url', ''))
            if content_type:
                response.headers['Content-Type'] = content_type
            return app_iter

        elif 'url' not in rsc:
            abort(404, _('No download is available'))
        redirect(rsc['url'])