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
 * This class provides an enumeration of hash algorithms that can
 * be used throughout the code. Each enumeration has a utility
 * function for creating a new instance of a Digest object
 * for that algorithm.
 */
public enum DigestAlgorithm
{
    /**
     * The enum for SHA1.
     */
    sha1(Sha1.class),

    /**
     * The enum for SHA256.
     */
    sha256(Sha256.class);



    /**
     * Constructor.
     */
    private DigestAlgorithm(
        Class _clss)
    {
        clss = _clss;
    }

    /**
     * The class used to generate objects
     */
    private Class clss;

    /**
     * Return the byte array identifying the OID.
     */
    public Digest newInstance()
    {
        try {return (Digest) clss.newInstance();}
        // By construction this shouldn't happen,
        // except perhaps an out-of-memory error.
        catch (Exception e) {return null;}
    }
};
