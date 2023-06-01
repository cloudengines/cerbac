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
 * @file cerbac/defaultdb.js
 * @author Brad Dietrich
 * @brief Cloud Engines Role Based Access Control
 */
'use strict'
const ceutil = require('@cloudengines/ceutil')
const log = ceutil.logger('xce:rbac')

function rolesForUser(tenantid, userid) {
  return []
}

function rolesForClient(tenantid, clientid) {
  return []
}

function rolesForAnonymous(tenantid) {
  return []
}

module.exports = {
  rolesForUser,
  rolesForClient,
  rolesForAnonymous
}
