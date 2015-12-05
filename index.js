'use strict';

var assert = require('assert');

var joi = require('joi');
var jwt = require('jsonwebtoken');
var boom = require('boom');
var nodefn = require('when/node');
var assign = require('origami').assign;
var rest = require('rest');
var mime = require('rest/interceptor/mime');
var template = require('rest/interceptor/template');
var errorCode = require('rest/interceptor/errorCode');
var defaultRequest = require('rest/interceptor/defaultRequest');

var optionsSchema = joi.object().keys({
  domain: joi.string().hostname().required(),
  clientId: joi.string().token().required(),
  clientSecret: joi.string().required(),
  redirectUri: joi.string().uri().required(),
  // TODO: can this be restricted?
  publicKey: joi.any()
}).rename('clientID', 'clientId', { ignoreUndefined: true })
  .rename('callbackURL', 'redirectUri', { ignoreUndefined: true })
  .options({ abortEarly: false });

function auth0LockWebappScheme(server, options){
  options = options || {};

  var result = joi.validate(options, optionsSchema);

  assert(!result.error, result.error && result.error.message);

  options = result.value; // validate & renamed properties object

  var client = rest
    .wrap(mime, { mime: 'application/x-www-form-urlencoded' })
    .wrap(template, { params: { domain: options.domain }})
    .wrap(errorCode)
    .wrap(defaultRequest, {
      path: 'https://{domain}/oauth/token',
      method: 'POST'
    });

  var secret = options.publicKey ? options.publicKey : new Buffer(options.clientSecret, 'base64');

  function decode(result){
    var token = result.id_token;
    return nodefn.call(jwt.verify, token, secret).fold(assign, { token: token });
  }

  return {
    authenticate: function(request, reply){
      var code = request.query.code;
      var state = request.query.state;

      if(!code){
        reply(boom.unauthorized('Missing code query parameter', 'Auth0-Lock-Webapp'));
        return;
      }

      var opts = {
        entity: {
          code: code,
          state: state,
          client_id: options.clientId,
          client_secret: options.clientSecret,
          redirect_uri: options.redirectUri,
          grant_type: 'authorization_code'
        }
      };

      function onSuccess(credentials){
        reply.continue({
          credentials: credentials
        });
      }

      function onError(err){
        var message = err.message || err.error_description;
        reply(boom.unauthorized(message, 'Auth0-Lock-Webapp'));
      }

      client(opts)
        .entity()
        .then(decode)
        .then(onSuccess, onError);
    }
  };
}

function hapiAuthAuth0LockWebapp(server, opts, done){
  server.auth.scheme('auth0-lock-webapp', auth0LockWebappScheme);
  done();
}

hapiAuthAuth0LockWebapp.attributes = {
  pkg: require('./package.json')
};

module.exports = {
  register: hapiAuthAuth0LockWebapp
};
