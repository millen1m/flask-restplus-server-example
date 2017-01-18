/**
 * This is an example of a basic node.js script that performs
 * the Authorization Code oAuth2 flow to authenticate against
 * the a Flask OAuth2 server.
 *
 * This file has intentional modified by https://github.com/millen1m
 * from the source taken from https://github.com/spotify/web-api-auth-examples
 */

var express = require('express');
var request = require('request');
var querystring = require('querystring');
var cookieParser = require('cookie-parser');

var client_id = 'documentation';
var client_secret = 'KQ()SWK)SQK)QWSKQW(SKQ)S(QWSQW(SJ*HQ&HQW*SQ*^SSQWSGQSG'; // client app secret
var redirect_uri = 'http://localhost:8888/callback'; // The redirect back to this client

var stateKey = 'flask_auth_state';

var app = express();

app.use(express.static(__dirname + '/public'))
   .use(cookieParser());

app.get('/login', function(req, res) {
  console.log("Log in button pressed");

  var state = "A_STATE_KEY_THAT_IS_FIXED_FOR_TESTING";  // have this auto-generate
  res.cookie(stateKey, state);

  // your application requests authorization
  var scope = 'users:write users:read auth:write teams:read teams:write auth:read';
  res.redirect('http://localhost:5000/auth/oauth2/authorize?' +
    querystring.stringify({
      response_type: 'code',
      client_id: client_id,
      type: 'GET',
      scope: scope,
      state: state,
      redirect_uri: redirect_uri
    }));
});

app.get('/logout', function(req, res) {
  console.log("Log out button pressed");

  res.redirect('http://localhost:5000/auth/logout')
});

app.get('/direct', function(req, res) {
  var authOptions = {
      url: 'http://127.0.0.1:5000/auth/oauth2/token?username=root&password=q',  // collect bearer token
      type: 'GET',
      form: {
        redirect_uri: redirect_uri,
        grant_type: 'password'
      },
      headers: {
        'Authorization': 'Basic ' + (new Buffer(client_id + ':' + client_secret).toString('base64'))
      },
      json: true,
      crossDomain: true
    };
  request.post(authOptions, function(error, response, body) {
      if (!error && response.statusCode === 200) {
        console.log("collected access token");
        console.log(body.access_token);
        //console.log(body);
        //console.log(response);

        var access_token = body.access_token,
            refresh_token = body.refresh_token;

        var options = {
          url: 'http://localhost:5000/api/v1/users/me',
          headers: { 'Authorization': 'Bearer ' + access_token },
          json: true
        };

        // use the access token to get user data
        request.get(options, function(error, response, body) {
          console.log(body);
        });

      } else {
        console.log("could not obtain API resources");
        res.redirect('/#' +
          querystring.stringify({
            error: 'invalid_token'
          }));
      }
    });
});

app.get('/callback', function(req, res) {

  var code = req.query.code || null;
  var state = req.query.state || null;
  var storedState = req.cookies ? req.cookies[stateKey] : null;
  console.log("On callback");
  console.log(req.cookies[stateKey]);
  console.log(req.query.state);
  console.log(req.query);


  if (state === null || state !== storedState) {
    res.redirect('/#' +
      querystring.stringify({
        error: 'state_mismatch'
      }));
  } else {
    res.clearCookie(stateKey);
    console.log("state key matches");
    var authOptions = {
      url: 'http://127.0.0.1:5000/auth/oauth2/token',  // collect bearer token
      type: 'GET',
      form: {
        code: code,
        redirect_uri: redirect_uri,
        grant_type: 'authorization_code'
      },
      headers: {
        'Authorization': 'Basic ' + (new Buffer(client_id + ':' + client_secret).toString('base64'))
      },
      json: true,
      crossDomain: true
    };

    request.post(authOptions, function(error, response, body) {
      if (!error && response.statusCode === 200) {
        console.log("collected access token");
        console.log(body.access_token);
        //console.log(body);
        //console.log(response);

        var access_token = body.access_token,
            refresh_token = body.refresh_token;

        var options = {
          url: 'http://localhost:5000/api/v1/users/me',
          headers: { 'Authorization': 'Bearer ' + access_token },
          json: true
        };

        // use the access token to get user data
        request.get(options, function(error, response, body) {
          console.log(body);
        });

      } else {
        console.log("could not obtain API resources");
        res.redirect('/#' +
          querystring.stringify({
            error: 'invalid_token'
          }));
      }
    });
  }
});

app.get('/refresh_token', function(req, res) {

  // requesting access token from refresh token
  var refresh_token = req.query.refresh_token;
  var authOptions = {
    url: 'http://localhost:5000/auth/oauth2/token',
    headers: { 'Authorization': 'Basic ' + (new Buffer(client_id + ':' + client_secret).toString('base64')) },
    form: {
      grant_type: 'refresh_token',
      refresh_token: refresh_token
    },
    json: true
  };

  request.post(authOptions, function(error, response, body) {
    if (!error && response.statusCode === 200) {
      var access_token = body.access_token;
      res.send({
        'access_token': access_token
      });
    }
  });
});

console.log('Listening on 8888');
app.listen(8888);
