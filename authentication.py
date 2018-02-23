from flask import Flask, request, make_response, abort, jsonify

from authenticators.basic_authentication import BasicAuthentication
from authenticators.token_authentication import TokenAuthentication
from validators.token_validation import TokenValidator
from validators.external_token_validation import ExternalTokenValidator
from revocators.token_revocation import TokenRevocator
from user import User
from settings import Config


app = Flask(__name__)


@app.route('/auth', methods=['GET'])
def auth_get():
    """Method to validate tokens and get information"""
    serv_token = request.headers.get('X-Service-Token')
    subj_token = request.headers.get('X-Subject-Token')
    ext_token = request.headers.get('X-External-Token')

    if serv_token is None:
        abort(400, description='service token must be provided')
    
    service = TokenValidator().validate_token(serv_token)

    if service is None or service.is_service is False:
        abort(400, description='validation must be done by service user')

    subj = TokenValidator().validate_token(subj_token)

    if subj is None:
        abort(404, description='subject token not found')
    
    if Config.EXTERNAL_MAPPING_VERIFICATION is True and ext_token is not None:
        ext = ExternalTokenValidator().validate_token(ext_token)

        if ext is None or ext.is_authenticated is False:
            abort(403, description='external token not authenticated')
    
    return make_response(jsonify(subj.to_public_dict()), 200)

@app.route('/auth', methods=['POST'])
def auth_post():
    """Method to authenticate users (using credentials or tokens)"""
    req_data = request.get_json()
    auth_method = req_data.get('method')
    subj_token = req_data.get('token')
    ext_token = req_data.get('external_token')
    auth_user = req_data.get('username')
    auth_pass = req_data.get('password')
    serv_token = request.headers.get('X-Service-Token')

    # Output
    resp_data = None
    gen_token = None

    if auth_method == 'password':
        if auth_user is not None and auth_pass is not None:    
            user = BasicAuthentication().authenticate(username=auth_user, password=auth_pass)

            if user is None:
                abort(404, description='user not found')

            if user.is_service is True:
                gen_token = user.token
                resp_data = user.to_public_dict()
            elif serv_token is not None:
                service = TokenValidator().validate_token(serv_token)

                if service is None or service.is_service is False:
                    TokenRevocator().revoke_token(user.token)
                    abort(403, description='user authentication must be done by service user')
                else:
                    if Config.EXTERNAL_MAPPING_VERIFICATION is True and ext_token is not None:
                        external = ExternalTokenValidator().validate_token(ext_token)

                        if external.is_authenticated is True:
                            gen_token = user.token
                            resp_data = user.to_public_dict()
                        else:
                            TokenRevocator().revoke_token(user.token)
                            abort(403, description='user authentication must match external service')
                    else:
                        gen_token = user.token
                        resp_data = user.to_public_dict()
            else:
                TokenRevocator().revoke_token(user.token)
                abort(403, description='user authentication must be done by service user')
        elif auth_user is None:
            abort(400, description='user must be provided')
        else:
            abort(400, description='password must be provided')
    elif auth_method == 'token':
        if subj_token is not None:
            user = TokenAuthentication().authenticate(token=subj_token)

            if user is None:
                abort(400, description='token not found')

            if user.is_service is True:
                gen_token = user.token
                resp_data = user.to_public_dict()
            elif serv_token is not None:
                service = TokenValidator().validate_token(serv_token)

                if service is None or service.is_service is False:
                    TokenRevocator().revoke_token(user.token)
                    abort(403, description='user authentication must be done by service user')
                else:
                    if Config.EXTERNAL_MAPPING_VERIFICATION is True:
                        external = ExternalTokenValidator().validate_token(ext_token)

                        if external.is_authenticated is True:
                            gen_token = user.token
                            resp_data = user.to_public_dict()
                        else:
                            TokenRevocator().revoke_token(user.token)
                            abort(403, description='user authentication must match external service')
                    else:
                        gen_token = user.token
                        resp_data = user.to_public_dict()
            else:
                TokenRevocator().revoke_token(user.token)
                abort(403, description='user authentication must be done by service user')
        else:
            abort(400, description='token must be provided')
    else:
        abort(400, description='method must be password or token')

    resp = make_response(jsonify(resp_data), 201)
    resp.headers['X-Subject-Token'] = gen_token

    return resp

@app.route('/auth', methods=['HEAD'])
def auth_head():
    """Method to validate tokens"""
    serv_token = request.headers.get('X-Service-Token')
    subj_token = request.headers.get('X-Subject-Token')
    ext_token = request.headers.get('X-External-Token')

    if serv_token is None:
        abort(400, description='service token must be provided')
    
    service = TokenValidator().validate_token(serv_token)

    if service is None or service.is_service is False:
        abort(400, description='validation must be done by service user')

    subj = TokenValidator().validate_token(subj_token)

    if subj is None:
        abort(404, description='subject token not found')
    
    if Config.EXTERNAL_MAPPING_VERIFICATION is True and ext_token is not None:
        ext = ExternalTokenValidator().validate_token(ext_token)

        if ext is None or ext.is_authenticated is False:
            abort(403, description='external token not authenticated')
    
    return make_response('', 200)

@app.route('/auth', methods=['DELETE'])
def auth_delete():
    """Method to revoke tokens"""
    serv_token = request.headers.get('X-Service-Token')
    subj_token = request.headers.get('X-Subject-Token')

    if serv_token is None:
        abort(400, description='service token must be provided')
    
    service = TokenValidator().validate_token(serv_token)

    if service is None or service.is_service is False:
        abort(400, description='revoking must be done by service user')

    if subj_token is None:
        abort(400, description='subject token must be provided')

    if TokenRevocator().revoke_token(subj_token):
        return make_response('token revoked', 204)
    else:
        abort(400, description='token could not be revoked')
