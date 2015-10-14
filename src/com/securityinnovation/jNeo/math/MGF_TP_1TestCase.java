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

package com.securityinnovation.jNeo.math;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.junit.Test;
import static org.junit.Assert.*;

import com.securityinnovation.testvectors.NtruEncryptTestVector;


public class MGF_TP_1TestCase {

    // Test the byte->trit converter with 1 input byte
    @Test public void test_decode_small()
    {
        byte input[] = {48};
        ByteArrayInputStream instream = new ByteArrayInputStream(input);
        
        FullPolynomial p = MGF_TP_1.genTrinomial(5, instream);
        short output[] = {0, 1, -1, 1, 0};

        assertArrayEquals(output, p.p);
    }


    // Test the byte->trit converter ignores values >= 243.
    @Test public void test_decode_skip_invalid_input()
    {
        byte input[] = {(byte)243, (byte)244, (byte)245, (byte)255, 48};
        ByteArrayInputStream instream = new ByteArrayInputStream(input);
        
        FullPolynomial p = MGF_TP_1.genTrinomial(5, instream);
        short output[] = {0, 1, -1, 1, 0};

        assertArrayEquals(output, p.p);
    }


    // Test the byte->trit converter correctly outputs trinomials whose length
    // is not a multiple of 5.
    @Test public void test_decode_misaligned_output()
    {
        byte input[] = {(byte)243, (byte)244, (byte)245, (byte)255, 48, 4};
        ByteArrayInputStream instream = new ByteArrayInputStream(input);
        
        FullPolynomial p = MGF_TP_1.genTrinomial(7, instream);
        short output[] = {0, 1, -1, 1, 0, 1, 1};

        assertArrayEquals(output, p.p);
    }


    // Test the trit->byte converter with the decoding of 1 byte
    @Test public void test_encode_small()
    {
        short input[] = {0, 1, -1, 1, 0};
        byte expectedOutput[] = {48};

        FullPolynomial p = new FullPolynomial(input);
        ByteArrayOutputStream out = new ByteArrayOutputStream(1);
        MGF_TP_1.encodeTrinomial(p, out);
        assertArrayEquals(expectedOutput, out.toByteArray());
    }


    // Test the trit->byte converter with a long stream whose
    // length is a multiple of 5.
    @Test public void test_encode_aligned_input()
    {
        short input[] = {
            1, 1, 1, 0, -1,     0, -1, -1, -1, 0,    0, 1, 0, 0, 1,
            0, 0, -1, 0, -1,    1, 0, 1, 0, 1,       0, -1, -1, -1, 0,
            -1, 1, 1, 0, 0,     0, -1, 0, 1, 0,      0, -1, -1, 0, 0,
            1, 0, 1, -1, 1,     -1, 1, 1, 1, 0,      0,  1, 1, -1, -1,
            0, 1, 0, 0, 0};
        byte expectedOutput[] = {
            (byte) 0xaf, (byte) 0x4e, (byte) 0x54,
            (byte) 0xb4, (byte) 0x5b, (byte) 0x4e,
            (byte) 0x0e, (byte) 0x21, (byte) 0x18,
            (byte) 0x91, (byte) 0x29, (byte) 0xe4,
            (byte) 0x03};

        FullPolynomial p = new FullPolynomial(input);
        ByteArrayOutputStream out = new ByteArrayOutputStream(1);
        MGF_TP_1.encodeTrinomial(p, out);
        assertArrayEquals(expectedOutput, out.toByteArray());
    }


    // Test the trit->byte converter with a long stream whose
    // length is not a multiple of 5.
    @Test public void test_encode_misaligned_input()
    {
        short input[] = {
            1, 1, 1, 0, -1,     0, -1, -1, -1, 0,    0, 1, 0, 0, 1,
            0, 0, -1, 0, -1,    1, 0, 1, 0, 1,       0, -1, -1, -1, 0,
            -1, 1, 1, 0, 0,     0, -1, 0, 1, 0,      0, -1, -1, 0, 0,
            1, 0, 1, -1, 1,     -1, 1, 1, 1, 0,      0,  1, 1, -1, -1,
            0, 1, 0, 0, 0,      0, -1};
        byte expectedOutput[] = {
            (byte) 0xaf, (byte) 0x4e, (byte) 0x54,
            (byte) 0xb4, (byte) 0x5b, (byte) 0x4e,
            (byte) 0x0e, (byte) 0x21, (byte) 0x18,
            (byte) 0x91, (byte) 0x29, (byte) 0xe4,
            (byte) 0x03, (byte) 0x06};

        FullPolynomial p = new FullPolynomial(input);
        ByteArrayOutputStream out = new ByteArrayOutputStream(1);
        MGF_TP_1.encodeTrinomial(p, out);
        assertArrayEquals(expectedOutput, out.toByteArray());
    }


    // Verify the byte->trit and trit->byte operations really
    // are inverses for a variety of trinomials.
    @Test public void test_invertibility()
    {
        NtruEncryptTestVector tests[] = NtruEncryptTestVector.getTestVectors();
        for (int t=0; t<tests.length; t++)
        {
            FullPolynomial p = new FullPolynomial(tests[t].F);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            MGF_TP_1.encodeTrinomial(p, out);
            ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
            FullPolynomial p2 = MGF_TP_1.genTrinomial(tests[t].F.length, in);
            assertArrayEquals(p.p, p2.p);
        }
    }

}

