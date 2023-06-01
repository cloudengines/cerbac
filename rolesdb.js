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
 * @file cerbac/rolesdb.js
 * @author Xavier Reese
 * @brief Cloud Engines RBAC Roles Database
 */
'use strict'

const core = require('cedb/core')
const ceutil = require('@cloudengines/ceutil')
const log = ceutil.logger('xce:rbac:rolesdb')

const _keys = {
  id: 'r_id',
  name: 'r_name',
  data: 'r_data',
  tenant: 'r_tid'
}

const _tableKeys = {
  id: 'ce_roles.r_id',
  name: 'ce_roles.r_name',
  data: 'ce_roles.r_data',
  tenant: 'ce_roles.r_tid'
}

function mapper(obj) {
  let role = {}
  role.id = obj.r_id.toString()
  role.name = obj.r_name.toString()
  if (obj.r_data !== null) role.rules = JSON.parse(obj.r_data.toString())
  return role
}

function hasProp(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop)
}

async function list(options) {
  let sql = 'SELECT * FROM ce_roles'
  let wc = core.where_helper(options, _keys, 'tenant')

  if (wc.clause) {
    sql += ' WHERE ' + wc.clause
  }

  log.debug('DB: roles.list: OPTIONS:', options, ' SQL: ', sql)

  return core.query_many(sql, wc.values, mapper)
}

async function get(id, options) {
  let values = [id]
  log.debug('get: ID:', id, 'OPTIONS:', options)
  let sql = 'SELECT * FROM ce_roles WHERE r_id = ?'
  if (options.tenant) {
    sql += ' AND (r_tid = ? OR r_tid = ?)'
    if (typeof options.tenant === 'string') {
      values.push(options.tenant)
    } else if (typeof options.tenant === 'object') {
      values.push(options.tenant.id)
    }
    values.push('0')
  }

  log.debug('roles.get: SQL: ', sql, ' VALUES: ', values)

  return core.query_one(sql, values, mapper)
}

async function listForUser(userid, options) {
  let sql =
    'SELECT ce_roles.r_id, ce_roles.r_name, ce_roles.r_data FROM ce_roles INNER JOIN ce_userroles ON ce_userroles.ur_rid = ce_roles.r_id WHERE ce_userroles.ur_uid = ?'
  //IF TENANT: ce_roles.r_tid,
  let values = [userid]
  let wc = core.where_helper(options, _tableKeys, 'tenant')
  if (wc.clause) {
    sql += ' WHERE ' + wc.clause
  }
  return core.query_many(sql, [values, ...wc.values], mapper)
}

async function listForClient(clientid, options) {
  let sql =
    'SELECT ce_roles.r_id, ce_roles.r_name, ce_roles.r_data FROM ce_roles INNER JOIN ce_clientroles ON ce_clientroles.cr_rid = ce_roles.r_id WHERE ce_clientroles.cr_cid = ?'
  //IF TID: ce_roles.r_tid,
  let values = [clientid]
  let wc = core.where_helper(options, _tableKeys, 'tenant')
  if (wc.clause) {
    sql += ' WHERE ' + wc.clause
  }
  return core.query_many(sql, [values, ...wc.values], mapper)
}

async function create(r) {
  if (!r.name /* || !(r.tenantid || (r.tenant && r.tenant.id))*/) {
    throw new Error('Required Values Missing')
  }

  /*if (!hasProp(r, 'tenant') && hasProp(r, 'tenantid')) {
    r.tenant = {
      id: r.tenantid
    }
  }*/

  let newRole = ceutil.patch({}, r)
  newRole.id = ceutil.genid()

  let fields = ['r_id', /*'r_tid', */ 'r_name']
  let values = [newRole.id, /*newRole.tenant.id, */ newRole.name]

  if (hasProp(r, 'permissions')) {
    fields.push('r_data')
    values.push(JSON.stringify(r.permissions))
  }

  log.debug('create: ID:', newRole.id /* ' TENANTID: ', newRole.tenant.id*/)
  const sql = 'INSERT INTO ce_roles (' + fields.join(', ') + ') VALUES (' + fields.map(x => '?').join(', ') + ')'
  log.debug('SQL: ', sql, ' VALUES: ', values)

  let aff = await core.query_aff(sql, values)

  if (aff > 0) {
    return newRole
  } else {
    log.error('Create Role: Query Error No Rows Affected: ', newRole.name)
    throw {code: 500, message: 'Failed Creating Role'}
    return
  }
}

async function del(r, options) {
  let rid = options.roleid
  if (typeof r != 'string') {
    rid = r.id
  }
  let sql = 'DELETE FROM ce_roles WHERE r_id = ?'
  let values = [rid]
  let wc = core.where_helper(options, _keys, 'tenant')

  if (wc.clause) {
    sql += ' AND ' + wc.clause
  }
  log.debug('roles.delete: SQL: ' + sql + ' VALUES: ' + [...values, ...wc.values])
  let aff = await core.query_aff(sql, [...values, wc.values], mapper)
  if (aff > 0) {
    return
  } else {
    log.error('Delete Role: Query Error No Rows Affected: Options: ', options, ' SQL: ', sql)
    throw {code: 404, message: 'Role Not Found'}
    return
  }
}

async function update(r, options) {
  let fields = []
  let values = []

  if (hasProp(r, 'name')) {
    fields.push('r_name')
    values.push(r.name)
  }
  if (hasProp(r, 'permissions')) {
    fields.push('r_data')
    values.push(JSON.stringify(r.permissions))
  }

  values.push(r.id)
  let sql = 'UPDATE ce_roles SET ' + fields.map(x => x + ' =?').join(', ') + ' WHERE r_id = ?'
  let wc = core.where_helper(options, _keys, 'tenant')
  if (wc.clause) {
    sql += ' AND ' + wc.clause
  }
  log.debug('roles.update: SQL: ', sql, ' VALUES: ', [...values, ...wc.values])
  let aff = await core.query_aff(sql, [...values, ...wc.values])

  if (aff > 0) {
    return
  } else {
    log.error('Update Role: Query Error No Rows Affected: Options: ', options)
    throw {code: 404, message: 'Role Not Found'}
    return
  }
}

async function addUserRoles(u, r) {
  await addRoles('user', u, r)
}

async function addClientRoles(c, r) {
  await addRoles('client', c, r)
}

async function addRoles(objType, objIDs, roleIDs) {
  let first
  let debugStatement
  if (objType === 'client') {
    first = 'c'
    debugStatement = 'addClientRoles'
  } else if (objType === 'user') {
    first = 'u'
    debugStatement = 'addUserRoles'
  }
  let sql = 'INSERT IGNORE INTO ce_' + objType + 'roles (' + first + 'r_' + first + 'id, ' + first + 'r_rid) VALUES '
  let values = []
  if (Array.isArray(objIDs) && Array.isArray(roleIDs)) {
    throw new Error('addRoles: Invalid Data')
  } else if (Array.isArray(roleIDs)) {
    sql += roleIDs
      .map(x => {
        values.push(objIDs, x)
        return '(?,?)'
      })
      .join(',')
  } else if (Array.isArray(objIDs)) {
    sql += objIDs
      .map(x => {
        values.push(x, roleIDs)
        return '(?,?)'
      })
      .join(',')
  } else {
    sql += '(?,?)'
    values.push(objIDs, roleIDs)
  }
  log.debug(debugStatement, ': SQL:', sql)
  log.debug(debugStatement, ': VAL:', values)
  let aff = await core.query_aff(sql, values)

  if (aff !== values.length / 2) {
    log.error(debugStatement, ': Query Error ' + aff + '/' + values.length / 2 + ' Rows Affected')
    throw {code: 500, message: 'Role(s) not Added'}
  }
  return
}

async function removeUserRoles(u, r) {
  await removeRoles('user', u, r)
}

async function removeClientRoles(c, r) {
  await removeRoles('client', c, r)
}

async function removeRoles(objType, objID, roleID) {
  let first
  let debug
  if (objType === 'client') {
    first = 'c'
    debug = 'removeClientRoles'
  } else if (objType === 'user') {
    first = 'u'
    debug = 'removeUserRoles'
  }

  let options = {}

  if (objID) {
    options.obj = {
      id: objID
    }
  }

  if (roleID) {
    options.role = {
      id: roleID
    }
  }

  let sql = 'DELETE FROM ce_' + objType + 'roles WHERE '
  let wc = core.where_helper(options, {
    obj: first + 'r_' + first + 'id',
    role: first + 'r_rid'
  })

  sql += wc.clause

  let aff = await core.query_aff(sql, wc.values)

  if (aff > 0) {
    return aff
  } else {
    log.debug('removeRoles: ', objType, ': No Rows Affected SQL: ', sql, ' VALUES: ', wc.values)
    return
  }
}

module.exports = {
  list,
  get,
  listForUser,
  listForClient,
  create,
  del,
  update,
  addUserRoles,
  addClientRoles,
  removeUserRoles,
  removeClientRoles
}
