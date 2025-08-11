/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * @name Use of MD5
 * @description Flags uses of the broken MD5 hash algorithm.
 * @kind problem
 * @id custom.md5-usage
 * @problem.severity warning
 * @precision medium
 */

import java

/** true if e is the string literal "MD5" (any case) */
predicate isMd5Literal(Expr e) {
  e instanceof StringLiteral and
  e.(StringLiteral).getValue().toLowerCase() = "md5"
}

from MethodAccess call
where
  // MessageDigest.getInstance("MD5")
  ( call.getMethod().hasQualifiedName("java.security", "MessageDigest", "getInstance") and
    isMd5Literal(call.getArgument(0))
  )
  or
  // Apache Commons Codec DigestUtils.md5*(...)
  call.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "DigestUtils") and
  call.getMethod().getName().regexpMatch("^md5.*$")
select call, "MD5 is a broken hash; prefer SHA-256/512 instead."
