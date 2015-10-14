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

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.jar.*;

public class ManifestBBTestCase
{
    static String jarfileName = "jars/jNeo.jar";

    String getAttribute(
        String attrName)
        throws java.io.IOException
    {
        JarFile jarfile = new JarFile(jarfileName);
        Manifest manifest = jarfile.getManifest();
        Attributes att = manifest.getMainAttributes();
        return att.getValue(attrName);
    }

    @Test public void test_implementation_vendor()
        throws java.io.IOException
    {
        assertEquals("Security Innovation",
                     getAttribute("Implementation-Vendor"));
    }
    
    @Test public void test_implementation_title()
        throws java.io.IOException
    {
        assertEquals("jNeo",
                     getAttribute("Implementation-Title"));
    }
    
    @Test public void test_implementation_version()
        throws java.io.IOException
    {
        assertEquals("1.0rc1",
                     getAttribute("Implementation-Version"));
    }
    
}
