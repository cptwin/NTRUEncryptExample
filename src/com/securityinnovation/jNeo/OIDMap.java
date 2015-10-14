/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved.
 *
 * Copyright (C) 2009-2013  Security Innovation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *********************************************************************************/

package com.securityinnovation.jNeo;

/**
 * This class exists to provide access to the
 * com.securityinnovation.jNeo.OID.getOIDBytes() method that has package-scope.
 *
 * <p>The problem this class is trying to solve is to provide access
 * to the OID.getOIDBytes() throughout the jNeo package and
 * sub-packages, while denying applications access to this
 * same data. 
 *
 * <p>Making OID.getOIDBytes() public generally is bad because
 * any code with access to the returned array can change
 * the contents of the array. We must not allow applications
 * to corrupt our internal data.
 *
 * <p>Making OID.getOIDBytes() public and then hiding it from the
 * application via post-processing of the jar file is not sufficient
 * because the method will still be displayed in the class' javadoc.
 *
 * <p>The solution arrived at is to make the method package-public,
 * define a class (OIDMap) that is public to the package to provide
 * indirect access to the OID.getOIDBytes() method, then remove OIDMap
 * from the public class list during post-processing of the jar file.
 * This is awkward but provides the right level of access to the data
 * and maintains javadoc consistency.
 */
public class OIDMap
{
    /**
     * Return the byte array identifying the OID.
     */
    public static byte[] getOIDBytes(
        OID oid)
    {
        return oid.getOIDBytes();
    }
}
