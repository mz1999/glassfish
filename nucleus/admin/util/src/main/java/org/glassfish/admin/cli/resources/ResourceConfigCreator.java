/*
 * Copyright (c) 2012, 2018 Oracle and/or its affiliates. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */

package org.glassfish.admin.cli.resources;

import java.lang.annotation.*;

/**
 * Created by IntelliJ IDEA. User: naman Date: 30/7/12 Time: 3:31 PM To change this template use File | Settings | File
 * Templates.
 */

/*
@ResourceConfigCreator annotation is used to indicate the creator of the resource.

The valid values can be a creator for a particular resource-type (eg: create-jdbc-resource, create-mail-resource)

While creating resource-ref for a particular resource-type, this commandName would be used to validate
the target type as not all resources might support all the targets.
 */
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Target(ElementType.TYPE)
public @interface ResourceConfigCreator {
    String commandName();
}
