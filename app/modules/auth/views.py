# coding: utf-8
"""
OAuth2 provider setup.

It is based on the code from the example:
https://github.com/lepture/example-oauth2-server

More details are available here:
* http://flask-oauthlib.readthedocs.org/en/latest/oauth2.html
* http://lepture.com/en/2013/create-oauth-server
"""

from flask import Blueprint, request, render_template, jsonify, session, redirect
from flask_login import current_user
import flask_login
import webargs
from werkzeug import exceptions as http_exceptions
from werkzeug import security

from app.extensions import db, api, oauth2, login_manager

from app.modules.users.models import User

from . import parameters
from .models import OAuth2Client
import logging

log = logging.getLogger('flask_oauthlib')

login_manager.login_view = "auth.login"


auth_blueprint = Blueprint('auth', __name__, url_prefix='/auth')  # pylint: disable=invalid-name


def get_current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    else:
        return User.query.get(1)

@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login(*args, **kwargs):
    if request.method == 'GET':  # Note: it is critical to not have the action parameter on the form
        return '''
               Please log in to access your account
               <form method='POST'>
                <input type='text' name='email' id='email' placeholder='email'></input>
                <input type='password' name='pw' id='pw' placeholder='password'></input>
                <input type='submit' name='submit'></input>
               </form>
               '''

    email = request.form['email']
    user = User.query.get(email)
    if request.form['pw']:
        user = User.find_with_password(request.form['email'], request.form['pw'])
        flask_login.login_user(user)
        next = request.args.get("next")
        if next is None:
            next = 'auth/protected'
        return redirect(next)

    return 'Bad login'


@auth_blueprint.route('/logout', methods=['GET', 'POST'])
@flask_login.login_required
def logout(*args, **kwargs):

    flask_login.logout_user()

    return '''
                <h1>You have successfully logged out</h1>
                Would you like to log in again?
               <form method='POST' action='login'>
                <input type='text' name='email' id='email' placeholder='email'></input>
                <input type='password' name='pw' id='pw' placeholder='password'></input>
                <input type='submit' name='login'></input>
               </form>
               '''

@auth_blueprint.route('/protected')
@flask_login.login_required
def protected():
    return 'Logged in as: ' + flask_login.current_user.username



@auth_blueprint.route('/oauth2/token', methods=['GET', 'POST'])
@oauth2.token_handler
def access_token(*args, **kwargs):
    # pylint: disable=unused-argument
    """
    This endpoint is for exchanging/refreshing an access token.

    Returns:
        response (dict): a dictionary or None as the extra credentials for
        creating the token response.
    """
    log.debug("requested token")


    return None

@auth_blueprint.route('/oauth2/revoke', methods=['POST'])
@oauth2.revoke_handler
def revoke_token():
    """
    This endpoint allows a user to revoke their access token.
    """
    pass


@auth_blueprint.route('/oauth2/errors', methods=['POST'])
def error_message():
    """
    This endpoint allows a user to revoke their access token.
    """
    log.debug("Error")
    pass

@oauth2.usergetter
def get_user(username, password, *args, **kwargs):
    user = User.query.filter_by(username=username).first()
    print("Running user getter")
    if user.check_password(password):
        return user
    return None


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@auth_blueprint.route('/oauth2/authorize', methods=['GET', 'POST'])
@flask_login.login_required
@oauth2.authorize_handler
def authorize(*args, **kwargs):
    # pylint: disable=unused-argument
    """
    This endpoint asks user if he grants access to his data to the requesting
    application.
    """
    log.debug("requested authorization")

    if not current_user.is_authenticated:
        log.debug(("NOT AUTHENTICATED"))
        return api.abort(code=http_exceptions.Unauthorized.code)

    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        log.debug("render authorizer")
        oauth2_client = OAuth2Client.query.filter_by(client_id=client_id).first()

        kwargs['client'] = oauth2_client
        kwargs['user'] = current_user
        # TODO: improve template design
        return render_template('authorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'
