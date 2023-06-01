/********************************************************************
 * Copyright 2018-2021 Cloud Engines, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * @file cerbac/index.js
 * @author Brad Dietrich
 * @brief Cloud Engines Role Based Access Control
 */
'use strict'
const ceutil = require('@cloudengines/ceutil')
const log = ceutil.logger('xce:rbac')

const defaultdb = require('./defaultdb.js')

// Process specific config
var pconfig = {
  logonly: true
}

// Process specific hooks
var phooks = {
  tenant: req => (req.xce && req.xce.tenant ? req.xce.tenant.id : undefined),
  user: req => (req.xce && req.xce.user ? req.xce.user.id : undefined),
  client: req => (req.xce ? req.xce.clientid : undefined),
  rolesForUser: defaultdb.rolesForUser,
  rolesForClient: defaultdb.rolesForClient,
  rolesForAnonymous: defaultdb.rolesForAnonymous
}

function evaluateRole(role, verb, group) {
  return role.rules.reduce((a, r) => {
    if (a) return a
    log.debug('RBAC: ' + verb + '(' + group + ')' + ', EVAL RULE: ' + role.id, JSON.stringify(r))
    if (r.group === '*' || r.group === group) {
      if (r.verb === '*' || r.verb === verb) {
        return true
      }
      if (r.verbs === '*' || (r.verbs.reduce && r.verbs.reduce((a, v) => a || v === verb))) {
        return true
      }
    }
    return false
  }, false)
}

// Invocking this function returns an asynchronous function that is is an
// express route function that is intended to preceed the actual implementation.
// The returned async function will validate that the calling request context
// has a sufficiently priviledged user credential to allow (i.e. role
// associated allows access to this verb on this group)
function express(verb, group, lconfig) {
  return async function(req, res, next) {
    let config = ceutil.patch({}, pconfig, lconfig)
    let targetstr = verb + '(' + group + ')'
    let idstr = ''

    try {
      let tenantid = await phooks.tenant(req)
      let userid = await phooks.user(req)
      let clientid = await phooks.client(req)

      if (tenantid !== undefined) {
        idstr = 'tenantid:' + tenantid + ' '
      }
      if (userid !== undefined) {
        idstr += 'userid:' + userid
      } else if (clientid !== undefined) {
        idstr += 'clientid:' + clientid
      } else {
        idstr += 'ANONYMOUS'
      }

      log.debug('RBAC: ' + targetstr + ', HOOKS:', phooks)
      log.debug('RBAC: ' + targetstr + ', CONFIG:', config)
      log.debug('RBAC: ' + targetstr + ', AUTH:', idstr)

      let roles
      if (userid !== undefined) {
        roles = await phooks.rolesForUser(tenantid, userid)
      } else if (clientid !== undefined) {
        roles = await phooks.rolesForClient(tenantid, clientid)
      } else {
        roles = await phooks.rolesForAnonymous(tenantid)
      }

      let canAccess = false
      if (!Array.isArray(roles)) {
        throw 'Hook returned unexpected roles value: ' + roles
      } else {
        log.debug(
          'RBAC: ' + targetstr + ', ROLES: ',
          roles.map(r => '' + r.id + ' ' + r.name)
        )

        canAccess = roles.reduce(
          (a, r) =>
            a ||
            (r => {
              log.debug('RBAC: ' + targetstr + ', EVAL ROLE: ' + r.id + ' ' + r.name)
              let x = evaluateRole(r, verb, group)
              log.debug('RBAC: ' + targetstr + ', EVAL RESULT: ', x)
              return x
            })(r),
          false
        )
      }

      if (canAccess) {
        next()
      } else {
        // Check if we are in enforce or in log only mode
        if (config.logonly) {
          log.warn('RBAC:', req.ip, req.method, req.path, 'LOG ONLY: Permission Denied:', targetstr, idstr)
          next()
        } else {
          log.warn('RBAC:', req.ip, req.method, req.path, 'Permission Denied:', targetstr, idstr)
          res.status(403)
          res.set('Content-Type', 'application/json')
          res.json({error: 403, errorMessage: 'Permission Denied'})
        }
      }
    } catch (e) {
      log.error('RBAC:', req.ip, req.method, req.path, 'EXCEPTION:', targetstr, idstr, e)
      if (config.logonly) {
        next()
      } else {
        res.status(403)
        res.set('Content-Type', 'application/json')
        res.json({error: 403, errorMessage: 'Permission Denied'})
      }
    }
  }
}

module.exports = {
  hooks: hooks => {
    log.debug('RBAC: Patching Hooks: ', hooks)
    phooks = ceutil.patch(phooks, hooks)
    return phooks
  },
  config: config => {
    ceutil.patch(pconfig, config)
    return pconfig
  },
  api: config => {
    let a = (verb, group) => {
      return express(verb, group, config)
    }
    return a
  }
}
