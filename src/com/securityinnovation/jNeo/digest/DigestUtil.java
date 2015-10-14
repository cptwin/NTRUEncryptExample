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

package com.securityinnovation.jNeo.digest;


/**
 * <p>This class holds utility methods for manipulating
 * <code>Digest</code> objects. These methods are public to
 * the com.securityinnovation.jNeo.digest package.
 */
public class DigestUtil
{
    /**
     * Create an instance of the specified Hash subclass using the 
     * default constructor.
     */
    public static Digest create(
        Class clss)
    {
        // The newInstance can fail if clss is not a subclass of Digest
        // or the clss is missing the default constructor.
        try {return (Digest) clss.newInstance();}
        catch (Exception e) {return null;}
    }
}

