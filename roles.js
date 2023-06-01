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
 * @file cerbac/roles.js
 * @author Xavier Reese
 * @brief Cloud Engines RBAC Roles API
 */
'use strict'
const ceutil = require('@cloudengines/ceutil')
const log = ceutil.logger('xce:rbac:rolesapi')
const rolesdb = require('./rolesdb.js')
const rbac = require('./core').api()

function outputError(req, res, status, msg, detail) {
  log.warn(req.method, req.path, 'Error:', status, msg, detail)
  res.status(status)
  res.set('Content-Type', 'application/json; charset=utf-8')
  res.json({error: status, errorMessage: msg, detail})
}

function pw(pf, cb) {
  return (req, res) => {
    log.debug(pf.name, req.method, req.path)
    pf(req, res)
      .then(x => {
        log.debug(pf.name, req.method, req.path, x)
        if (cb) cb(x)
      })
      .catch(e => {
        log.error('Exception in', pf.name, req.method, req.path, e.stack)
        outputError(req, res, 500, 'Unhandled Server Error', {e: e.message})
      })
  }
}

function outputArrayStream(res, stream, firstcb, endcb) {
  var first = true
  stream.on('data', obj => {
    if (first) {
      first = false
      if (firstcb) firstcb()
      res.write('[')
    } else {
      res.write(',')
    }
    res.write(JSON.stringify(obj))
  })
  stream.on('end', () => {
    // Notify completion
    if (first) {
      first = false
      if (firstcb) firstcb()
      res.write('[')
    }
    res.write(']')
    if (endcb) endcb()
  })
  stream.on('error', err => {
    log.error(err.stack)
  })
}

/////////////////////////////////////////////////////
// API for Roles

async function listRoles(req, res) {
  let options = {}

  let roles = await rolesdb.list(options)

  if (roles && roles.length > 0) {
    res.json({roles: roles})
  } else {
    outputError(req, res, 404, 'Not Found')
  }
}

async function getRole(req, res) {
  const roleid = req.params.roleid
  let options = {}
  rolesdb.get(roleid, options, (err, r) => {
    if (r) {
      res.json(r)
    } else {
      outputError(req, res, 404, 'No Role "' + roleid + '"')
    }
  })
}

async function updateRole(req, res) {
  let options = {
    id: req.params.roleid
  }

  let role = req.body

  await rolesdb.update(role, options)

  res.status(204)
  res.end()
}

async function deleteRole(req, res) {
  let options = {id: req.params.roleid}
  let aff = await db.quizquestions.del(options)

  res.status(204)
  res.end()
}

async function createRole(req, res) {
  let newRole = req.body
  debug('Creating Role:', newRole)

  if (!newRole.name || !newRole.permissions || !newRole.tenant || !newRole.tenant.id) {
    outputError(req, res, 400, 'Required Values Missing')
    return
  }

  let r = await rolesdb.create(newRole)

  res.header('Location', '/v1/roles/' + r.id)
  res.status(201)
  res.json(r)
}

//////////////////////////////////////////////////////
// API for Roles in other heirarchies

async function api_getForUser(req, res) {
  // res.set('Content-Type', 'application/json')

  let options = {}

  let roles = await rolesdb.listForUser(req.params.userid, options)

  if (roles && roles.length > 0) {
    res.json({roles: roles})
  } else {
    outputError(req, res, 404, 'Not Found')
  }

  // const stream = rolesdb.listForUser(options)
  // outputArrayStream(
  //   res,
  //   stream,
  //   () => {
  //     res.write('{"roles":')
  //   },
  //   () => {
  //     res.write('}')
  //     res.end()
  //   }
  // )
  // stream.on('error', err => {
  //   throw err
  // })
}

async function api_getForClient(req, res) {
  const clientidid = req.params.clientidid
  // res.set('Content-Type', 'application/json')

  let options = {}

  let roles = await rolesdb.listForClient(options)

  if (roles && roles.length > 0) {
    res.json({roles: roles})
  } else {
    outputError(req, res, 404, 'Not Found')
  }

  // db.clientids.get(clientidid, options, (err, c) => {
  //   if (c) {
  //     const stream = rolesdb.listForClient(clientidid, options)
  //     outputArrayStream(
  //       res,
  //       stream,
  //       () => {
  //         res.write('{"roles":')
  //       },
  //       () => {
  //         res.write('}')
  //         res.end()
  //       }
  //     )
  //     stream.on('error', err => {
  //       throw err
  //     })
  //   } else {
  //     outputError(req, res, 404, 'No Client ID "' + clientidid + '"')
  //   }
  // })
}

//////////////////////////////////////////////////////
// Exports

function setup(api) {
  api
    .route('/roles/')
    .post(rbac('create', 'role'), pw(createRole))
    .get(rbac('read', 'role'), pw(listRoles))

  api
    .route('/roles/:roleid')
    .get(rbac('read', 'role'), pw(getRole))
    .put(rbac('update', 'role'), pw(updateRole))
    .delete(rbac('delete', 'role'), pw(deleteRole))
}

module.exports = {
  setup,
  api_getForUser,
  api_getForClient
}
