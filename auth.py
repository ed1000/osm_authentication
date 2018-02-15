from flask import Flask, request, make_response, abort, jsonify

from authenticators.basic_authentication import BasicAuthentication
from authenticators.token_authentication import TokenAuthentication
from validators.token_validation import TokenValidator
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
        return make_response('service token must be provided.', 400)
    
    service = TokenValidator().validate_token(serv_token)

    if service is None or service.is_service is False:
        return make_response('validation must be done by service user', 400)

    subj = TokenValidator().validate_token(subj_token)

    if subj is None:
        return make_response('subj token not found', 404)
    
    if Config.EXTERNAL_MAPPING_VERIFICATION is True and ext_token is not None:
        # TODO: Verify external mapping
        pass
    
    return make_response(subj.to_public_dict(), 200)

@app.route('/auth', methods=['POST'])
def auth_post():
    """Method to authenticate users (using credentials or tokens)"""
    req_data = request.get_json()
    auth_method = req_data.get('method')

    resp_data = None
    gen_token = None

    if auth_method == 'password':
        serv_token = request.headers.get('X-Service-Token')
        auth_user = req_data.get('user')
        auth_pass = req_data.get('password')

        if auth_user is not None and auth_pass is not None:    
            user = BasicAuthentication().authenticate(username=auth_user,password=auth_pass)

            if user is None:
                return make_response('user not found.', 404)

            if user.is_service is True:
                gen_token = user.token
                resp_data = user.to_public_dict()
            elif serv_token is not None:
                service = TokenValidator().validate_token(serv_token)

                if service is None or service.is_service is False:
                    TokenRevocator().revoke_token(user.token)
                    return make_response('user authentication must be done by service user', 400)
                else:
                    if Config.EXTERNAL_MAPPING_VERIFICATION is True:
                        # TODO: Externally verify user
                        pass
                    else:
                        gen_token = user.token
                        resp_data = user.to_public_dict()
            else:
                TokenRevocator().revoke_token(user.token)
                return make_response('user authentication must be done by service user', 400)
        elif auth_user is None:
            return make_response('user must be provided.', 400)
        else:
            return make_response('password must be provided.', 400)
    elif auth_method == 'token':
        serv_token = request.headers.get('X-Service-Token')
        auth_token = req_data.get('token')

        if auth_token is not None:
            user = TokenAuthentication().authenticate(token=auth_token)

            if user is None:
                return make_response('token not found.', 404)

            if user.is_service is True:
                gen_token = user.token
                resp_data = user.to_public_dict()
            elif serv_token is not None:
                service = TokenValidator().validate_token(serv_token)

                if service is None or service.is_service is False:
                    TokenRevocator().revoke_token(user.token)
                    return make_response('user authentication must be done by service user', 400)
                else:
                    if Config.EXTERNAL_MAPPING_VERIFICATION is True:
                        # TODO: Externally verify user
                        pass
                    else:
                        gen_token = user.token
                        resp_data = user.to_public_dict()
            else:
                TokenRevocator().revoke_token(user.token)
                return make_response('user authentication must be done by service user', 400)
        else:
            return make_response('token must be provided.', 400)
    else:
        return make_response('method must be password or token.', 400)

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
        return make_response('service token must be provided.', 400)
    
    service = TokenValidator().validate_token(serv_token)

    if service is None or service.is_service is False:
        return make_response('validation must be done by service user', 400)

    subj = TokenValidator().validate_token(subj_token)

    if subj is None:
        return make_response('subject token not found', 404)
    
    if Config.EXTERNAL_MAPPING_VERIFICATION is True and ext_token is not None:
        # TODO: Verify external mapping
        pass
    
    return make_response('', 200)

@app.route('/auth', methods=['DELETE'])
def auth_delete():
    """Method to revoke tokens"""
    serv_token = request.headers.get('X-Service-Token')
    subj_token = request.headers.get('X-Subject-Token')

    if serv_token is None:
        return make_response('service token must be provided.', 400)
    
    service = TokenValidator().validate_token(serv_token)

    if service is None or service.is_service is False:
        return make_response('validation must be done by service user', 400)

    if subj_token is None:
        return make_response('subject token must be provided.', 400)

    if TokenRevocator().revoke_token(subj_token):
        return make_response('token revoked.', 204)
    else:
        return make_response('token could not be revoked.', 400)
