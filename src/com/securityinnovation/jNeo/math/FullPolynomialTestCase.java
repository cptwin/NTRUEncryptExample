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

import org.junit.Test;
import static org.junit.Assert.*;

import com.securityinnovation.jNeo.ParamSetNotSupportedException;
import com.securityinnovation.jNeo.ntruencrypt.KeyParams;
import com.securityinnovation.testvectors.NtruEncryptTestVector;


public class FullPolynomialTestCase {

    // Test recentering to 0 and to a non-zero value.
    @Test public void test_recenterModQ_0()
    {
        short aCoeffs[] = {1, 2, 3, 4, 5, 6, 7, 8};
        FullPolynomial a = new FullPolynomial(aCoeffs);
        FullPolynomial.recenterModQ(a, 4, 0);
        short expectedCoeffs[] = {1, 2, 3, 0, 1, 2, 3, 0};
        assertArrayEquals(a.p, aCoeffs);
    }
    @Test public void test_recenterModQ_2()
    {
        short aCoeffs[] = {1, 2, 3, 4, 5, 6, 7, 8};
        FullPolynomial a = new FullPolynomial(aCoeffs);
        FullPolynomial.recenterModQ(a, 4, -2);
        short expectedCoeffs[] = {1, -2, -1, 0, 1, -2, -1, 0};
        assertArrayEquals(a.p, aCoeffs);
    }

    // Test convolution without limiting the coefficients
    @Test public void test_basic_convolution_x1()
    {
        short aCoeffs[] = {1, 0, 1, 0};
        short bCoeffs[] = {1, 0, 0, 0}; // f(x) = 1
        FullPolynomial p = FullPolynomial.convolution(
            new FullPolynomial(aCoeffs), new FullPolynomial(bCoeffs));
        assertArrayEquals(aCoeffs, p.p);
    }
    @Test public void test_basic_convolution_xX()
    {
        short aCoeffs[] = {1, 0, 1, 0};
        short bCoeffs[] = {0, 1, 0, 0}; // f(x) = x
        short expectedCoeffs[] = {0, 1, 0, 1};
        FullPolynomial p = FullPolynomial.convolution(
            new FullPolynomial(aCoeffs), new FullPolynomial(bCoeffs));
        assertArrayEquals(expectedCoeffs, p.p);
    }
    @Test public void test_basic_convolution_3x_2x2()
    {
        short aCoeffs[] = {10, 0, 5, 0};
        short bCoeffs[] = {0, 3, 2, 0}; // f(x) = 3x + 2x^2
        short expectedCoeffs[] = {10, 30, 20, 15};
        FullPolynomial p = FullPolynomial.convolution(
            new FullPolynomial(aCoeffs), new FullPolynomial(bCoeffs));
        assertArrayEquals(expectedCoeffs, p.p);
    }


    // Test convolution limiting the coefficients modlulo q.
    // Use samples from the NtruEncrypt test vector paper:
    //  R = r * h (mod q)
    @Test public void test_convolution()
        throws ParamSetNotSupportedException
    {
        NtruEncryptTestVector tests[] = NtruEncryptTestVector.getTestVectors();
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            FullPolynomial r = new FullPolynomial(tests[t].r);
            FullPolynomial h = new FullPolynomial(tests[t].h);
            FullPolynomial R = new FullPolynomial(tests[t].R);

            FullPolynomial out = FullPolynomial.convolution(r, h, keyParams.q);
            assertTrue(out.equals(R));
        }
    }


    // Use samples from the NtruEncrypt test vector paper:
    //  e = R + m' (mod q)
    @Test public void test_add()
        throws ParamSetNotSupportedException
    {
        NtruEncryptTestVector tests[] = NtruEncryptTestVector.getTestVectors();
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            FullPolynomial R  = new FullPolynomial(tests[t].R);
            FullPolynomial mP = new FullPolynomial(tests[t].mPrime);
            FullPolynomial e  = new FullPolynomial(tests[t].e);

            FullPolynomial out = FullPolynomial.add(R, mP, keyParams.q);
            assertTrue(out.equals(e));
        }
    }


    // Use samples from the NtruEncrypt test vector paper:
    //   m' = M + mask (mod p) centered on 0.
    @Test public void test_addAndRecenter()
        throws ParamSetNotSupportedException
    {
        NtruEncryptTestVector tests[] = NtruEncryptTestVector.getTestVectors();
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);

            // m' = mask + Mtrin (mod p)
            FullPolynomial mask = new FullPolynomial(tests[t].mask);
            FullPolynomial Mtrin = new FullPolynomial(tests[t].Mtrin);

            FullPolynomial out = 
              FullPolynomial.addAndRecenter(mask, Mtrin, keyParams.p, -1);

            FullPolynomial mP = new FullPolynomial(tests[t].mPrime);
            assertTrue(out.equals(mP));
        }
    }



    // Use samples from the NtruEncrypt test vector paper:
    //  R = e - m' (mod q)
    @Test public void test_subtract()
        throws ParamSetNotSupportedException
    {
        NtruEncryptTestVector tests[] = NtruEncryptTestVector.getTestVectors();
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);
            FullPolynomial R  = new FullPolynomial(tests[t].R);
            FullPolynomial mP = new FullPolynomial(tests[t].mPrime);
            FullPolynomial e  = new FullPolynomial(tests[t].e);

            FullPolynomial out = FullPolynomial.subtract(e, mP, keyParams.q);
            assertTrue(out.equals(R));
        }
    }


    // Use samples from the NtruEncrypt test vector paper:
    //   m' - mask = M (mod p) centered on 0.
    @Test public void test_subtractAndRecenter()
        throws ParamSetNotSupportedException
    {
        NtruEncryptTestVector tests[] = NtruEncryptTestVector.getTestVectors();
        for (int t=0; t<tests.length; t++)
        {
            KeyParams keyParams = KeyParams.getKeyParams(tests[t].oid);

            // m' = mask + Mtrin (mod p)
            FullPolynomial mask = new FullPolynomial(tests[t].mask);
            FullPolynomial Mtrin = new FullPolynomial(tests[t].Mtrin);
            FullPolynomial mP = new FullPolynomial(tests[t].mPrime);

            FullPolynomial out = 
              FullPolynomial.subtractAndRecenter(mP, mask, keyParams.p, -1);

            assertTrue(out.equals(Mtrin));
        }
    }


    @Test public void test_equals_hashCode()
    {
        short a1Bytes[] = {0, 1, 2, 3, 4, 5};
        short a2Bytes[] = {0, 1, 2, 3, 4, 5};
        FullPolynomial a1 = new FullPolynomial(a1Bytes);
        FullPolynomial a2 = new FullPolynomial(a2Bytes);
        assertTrue(a1.equals(a2));
        assertTrue(a1.hashCode() == a2.hashCode());

        // Make the polynomials differ
        a2.p[0]++;
        assertFalse(a1.equals(a2));
        assertTrue(a1.hashCode() != a2.hashCode());
    }
}

